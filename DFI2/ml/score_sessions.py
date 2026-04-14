#!/usr/bin/env python3
"""Session-level batch scorer for PV1.

Cron: 2-57/5 * * * *
Scores sessions with new flows in last 10 minutes.
Does NOT replace per-flow scoring — runs as second layer alongside CNN v3 + evil_02_tcp.

Pattern: score.py + score_dirty_evidence.py

Usage:
    python3 score_sessions.py /opt/dfi2/ml/models/session_xgb_v1.json
    python3 score_sessions.py /opt/dfi2/ml/models/session_xgb_v1.json --hours 24
"""
import argparse
import os
import re
import time
from datetime import datetime

import numpy as np
import xgboost as xgb
from clickhouse_driver import Client

CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))
BATCH_SIZE = 100000
NTHREAD = 80  # PV1 = 80 cores

# 31 session features — must match train_xgb.py SESSION_FEAT_COLS
SESSION_FEAT_COLS = [
    'sess_flow_count', 'sess_bytes_fwd', 'sess_bytes_rev',
    'sess_pkts_fwd', 'sess_pkts_rev', 'sess_reply_ratio',
    'sess_duration', 'sess_avg_iat', 'sess_min_iat', 'sess_max_iat', 'sess_avg_flow_dur',
    'sess_max_flow_dur', 'sess_max_bytes_rev', 'sess_avg_bytes_per_flow',
    'sess_payload_ratio', 'sess_bidirectional_ratio',
    'sess_syn_only_ratio', 'sess_rst_ratio', 'sess_completed_ratio', 'sess_avg_tcp_flags',
    'src_total_sessions', 'src_total_ports', 'src_total_flows',
    'src_avg_session_depth', 'src_single_flow_sessions', 'src_reply_rate',
    'prior_scan_count', 'prior_brute_count', 'prior_exploit_count',
    'time_since_first_seen', 'max_prior_stage',
]


def classify_stage(sess):
    """Classify session kill chain stage from features."""
    fc = sess.get('sess_flow_count', 0)
    syn_ratio = sess.get('sess_syn_only_ratio', 0)
    reply_ratio = sess.get('sess_reply_ratio', 0)
    bidir_ratio = sess.get('sess_bidirectional_ratio', 0)
    max_flow_dur = sess.get('sess_max_flow_dur', 0)
    max_bytes_rev = sess.get('sess_max_bytes_rev', 0)
    duration = sess.get('sess_duration', 0)

    if duration > 300 and fc > 5 and bidir_ratio > 0.3:
        return 4  # C2
    if bidir_ratio > 0.5 and max_flow_dur > 30000 and max_bytes_rev > 1024:
        return 3  # EXPLOIT
    if fc > 20 and 0.3 < reply_ratio < 0.7:
        return 2  # BRUTE
    if fc <= 3 and syn_ratio > 0.5 and reply_ratio < 0.2:
        return 1  # RECON
    return 0


def parse_timestamp_array(s):
    """Parse CH groupArray output to epoch seconds."""
    if s is None or s == '[]':
        return []
    s = str(s).strip('[]')
    parts = re.findall(r"'([^']+)'", s)
    if not parts:
        parts = [p.strip() for p in s.split(',') if p.strip()]
    epochs = []
    for p in parts:
        for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S'):
            try:
                dt = datetime.strptime(p.strip(), fmt)
                epochs.append(dt.timestamp())
                break
            except ValueError:
                continue
    return sorted(epochs)


def compute_iat(timestamps):
    """Compute avg/min/max IAT from sorted timestamps."""
    if len(timestamps) < 2:
        return 0.0, 0.0, 0.0
    diffs = np.diff(timestamps)
    return float(np.mean(diffs)), float(np.min(diffs)), float(np.max(diffs))


def fetch_session_features(ch, minutes=10):
    """Fetch session features for sessions with recent activity."""
    query = f"""
    SELECT
        src_ip, dst_ip, dst_port,
        countMerge(flow_count)  AS sess_flow_count,
        sumMerge(sum_bytes_fwd) AS sess_bytes_fwd,
        sumMerge(sum_bytes_rev) AS sess_bytes_rev,
        sumMerge(sum_pkts_fwd)  AS sess_pkts_fwd,
        sumMerge(sum_pkts_rev)  AS sess_pkts_rev,
        if(sumMerge(sum_pkts_fwd) > 0,
           sumMerge(sum_pkts_rev) / sumMerge(sum_pkts_fwd), 0) AS sess_reply_ratio,
        dateDiff('second', minMerge(first_seen), maxMerge(last_seen)) AS sess_duration,
        if(countMerge(flow_count) > 0,
           sumMerge(sum_duration) / countMerge(flow_count), 0) AS sess_avg_flow_dur,
        maxMerge(max_duration) AS sess_max_flow_dur,
        maxMerge(max_bytes_rev) AS sess_max_bytes_rev,
        if(countMerge(flow_count) > 0,
           (sumMerge(sum_bytes_fwd) + sumMerge(sum_bytes_rev)) / countMerge(flow_count), 0) AS sess_avg_bytes_per_flow,
        if((sumMerge(sum_bytes_fwd) + sumMerge(sum_bytes_rev)) > 0,
           sumMerge(sum_bytes_rev) / (sumMerge(sum_bytes_fwd) + sumMerge(sum_bytes_rev)), 0) AS sess_payload_ratio,
        if(countMerge(flow_count) > 0,
           sumIfMerge(sum_bidir) / countMerge(flow_count), 0) AS sess_bidirectional_ratio,
        if(countMerge(flow_count) > 0,
           sumIfMerge(sum_conn_state_0) / countMerge(flow_count), 0) AS sess_syn_only_ratio,
        if(countMerge(flow_count) > 0,
           sumMerge(sum_rst) / countMerge(flow_count), 0) AS sess_rst_ratio,
        if(countMerge(flow_count) > 0,
           sumIfMerge(sum_conn_state_4) / countMerge(flow_count), 0) AS sess_completed_ratio,
        if(countMerge(flow_count) > 0,
           (sumMerge(sum_syn) + sumMerge(sum_fin) + sumMerge(sum_rst) + sumMerge(sum_psh))
               / countMerge(flow_count), 0) AS sess_avg_tcp_flags,
        minMerge(first_seen) AS _first_seen,
        maxMerge(last_seen) AS _last_seen
    FROM dfi.session_stats
    GROUP BY src_ip, dst_ip, dst_port
    HAVING maxMerge(last_seen) >= now() - INTERVAL {minutes} MINUTE
    """
    rows = ch.execute(query, with_column_types=True)
    cols = [c[0] for c in rows[1]]
    return [dict(zip(cols, r)) for r in rows[0]]


def fetch_timestamps_for_sessions(ch, sessions):
    """Fetch flow timestamps for IAT computation."""
    if not sessions:
        return {}
    # Batch by src_ip to avoid huge IN clauses
    src_ips = list(set(str(s['src_ip']) for s in sessions))
    ts_map = {}

    for batch_start in range(0, len(src_ips), 1000):
        batch_ips = src_ips[batch_start:batch_start + 1000]
        rows = ch.execute(
            """
            SELECT src_ip, dst_ip, dst_port, groupArray(first_ts) AS ts_arr
            FROM dfi.flows
            WHERE src_ip IN %(ips)s
            GROUP BY src_ip, dst_ip, dst_port
            """,
            {'ips': batch_ips},
        )
        for r in rows:
            key = (str(r[0]), str(r[1]), int(r[2]))
            ts_list = r[3] if isinstance(r[3], list) else parse_timestamp_array(r[3])
            if isinstance(ts_list, list) and ts_list and isinstance(ts_list[0], datetime):
                ts_map[key] = sorted(t.timestamp() for t in ts_list)
            else:
                ts_map[key] = sorted(float(t) for t in ts_list) if ts_list else []
    return ts_map


def compute_source_context(sessions):
    """Compute F5 Source Context features across all sessions."""
    # Group by src_ip
    src_groups = {}
    for s in sessions:
        src = str(s['src_ip'])
        if src not in src_groups:
            src_groups[src] = []
        src_groups[src].append(s)

    src_ctx = {}
    for src, group in src_groups.items():
        total_sessions = len(group)
        total_ports = len(set(s['dst_port'] for s in group))
        total_flows = sum(s.get('sess_flow_count', 0) for s in group)
        avg_depth = total_flows / total_sessions if total_sessions > 0 else 0
        single_flow = sum(1 for s in group if s.get('sess_flow_count', 0) == 1)
        reply_rates = [s.get('sess_reply_ratio', 0) for s in group]
        avg_reply = sum(reply_rates) / len(reply_rates) if reply_rates else 0

        src_ctx[src] = {
            'src_total_sessions': total_sessions,
            'src_total_ports': total_ports,
            'src_total_flows': total_flows,
            'src_avg_session_depth': avg_depth,
            'src_single_flow_sessions': single_flow,
            'src_reply_rate': avg_reply,
        }
    return src_ctx


def compute_kill_chain_history(sessions):
    """Compute F6 Kill Chain History for each session."""
    # Group by src_ip, sort by timestamp
    src_groups = {}
    for i, s in enumerate(sessions):
        src = str(s['src_ip'])
        if src not in src_groups:
            src_groups[src] = []
        first_seen = s.get('_first_seen')
        if isinstance(first_seen, datetime):
            epoch = first_seen.timestamp()
        elif first_seen is not None:
            epoch = float(first_seen)
        else:
            epoch = 0
        src_groups[src].append((epoch, i, classify_stage(s)))

    # Sort each group by time
    for src in src_groups:
        src_groups[src].sort(key=lambda x: x[0])

    # Compute rolling history per src_ip
    history = {}
    for src, group in src_groups.items():
        first_epoch = group[0][0] if group else 0
        prior_stages = []
        for epoch, idx, stage in group:
            scan_cnt = sum(1 for s in prior_stages if s == 1)
            brute_cnt = sum(1 for s in prior_stages if s == 2)
            exploit_cnt = sum(1 for s in prior_stages if s >= 3)
            max_s = max(prior_stages, default=0)
            t_since = epoch - first_epoch if first_epoch > 0 and epoch > 0 else 0

            history[idx] = {
                'prior_scan_count': scan_cnt,
                'prior_brute_count': brute_cnt,
                'prior_exploit_count': exploit_cnt,
                'time_since_first_seen': max(t_since, 0),
                'max_prior_stage': max_s,
                '_kill_chain_stage': stage,
            }
            prior_stages.append(stage)

    return history


def score(model_path, model_version, ch, minutes=10):
    """Score recent sessions."""
    t0 = time.time()

    # Load model
    bst = xgb.Booster({'nthread': NTHREAD})
    bst.load_model(model_path)
    feat_names = bst.feature_names
    if feat_names is None:
        feat_names = SESSION_FEAT_COLS
    print(f'Model features: {len(feat_names)}')

    # 1. Fetch session features
    sessions = fetch_session_features(ch, minutes=minutes)
    if not sessions:
        print('No sessions to score')
        return 0
    print(f'Sessions to score: {len(sessions):,}')

    # 2. Fetch timestamps for IAT
    ts_map = fetch_timestamps_for_sessions(ch, sessions)

    # 3. Compute IAT features
    for s in sessions:
        key = (str(s['src_ip']), str(s['dst_ip']), int(s['dst_port']))
        timestamps = ts_map.get(key, [])
        avg_iat, min_iat, max_iat = compute_iat(timestamps)
        s['sess_avg_iat'] = avg_iat
        s['sess_min_iat'] = min_iat
        s['sess_max_iat'] = max_iat

    # 4. Compute F5 source context
    src_ctx = compute_source_context(sessions)
    for s in sessions:
        ctx = src_ctx.get(str(s['src_ip']), {})
        s.update(ctx)

    # 5. Compute F6 kill chain history
    kc_history = compute_kill_chain_history(sessions)
    for i, s in enumerate(sessions):
        h = kc_history.get(i, {})
        s.update({k: v for k, v in h.items() if not k.startswith('_')})
        s['_kill_chain_stage'] = h.get('_kill_chain_stage', 0)

    # 6. Build feature matrix
    X = np.zeros((len(sessions), len(feat_names)), dtype=np.float32)
    for i, s in enumerate(sessions):
        for j, col in enumerate(feat_names):
            val = s.get(col, 0)
            if val is None:
                val = 0
            X[i, j] = float(val)

    # 7. Score
    dmat = xgb.DMatrix(X, feature_names=feat_names, nthread=NTHREAD)
    proba = bst.predict(dmat)
    preds = (proba > 0.5).astype(int)
    confs = np.where(preds == 1, proba, 1.0 - proba)

    # 8. Write predictions
    pred_rows = []
    for i, s in enumerate(sessions):
        pred_rows.append({
            'src_ip': str(s['src_ip']),
            'dst_ip': str(s['dst_ip']),
            'dst_port': int(s['dst_port']),
            'model_name': 'session_xgb_v1',
            'model_version': model_version,
            'label': int(preds[i]),
            'confidence': float(confs[i]),
            'kill_chain_stage': int(s.get('_kill_chain_stage', 0)),
        })

    # Batch insert
    for batch_start in range(0, len(pred_rows), BATCH_SIZE):
        batch = pred_rows[batch_start:batch_start + BATCH_SIZE]
        ch.execute(
            'INSERT INTO dfi.session_predictions '
            '(src_ip, dst_ip, dst_port, model_name, model_version, label, confidence, kill_chain_stage) '
            'VALUES',
            batch,
        )

    n_evil = int(preds.sum())
    elapsed = time.time() - t0
    print(f'Scored {len(sessions):,} sessions ({n_evil:,} evil, {len(sessions)-n_evil:,} clean) in {elapsed:.1f}s')

    # Summary by kill chain stage
    stages = {0: 'NONE', 1: 'RECON', 2: 'BRUTE', 3: 'EXPLOIT', 4: 'C2'}
    for stage_id, stage_name in stages.items():
        stage_preds = [p for i, p in enumerate(preds) if sessions[i].get('_kill_chain_stage', 0) == stage_id]
        if stage_preds:
            n_stage = len(stage_preds)
            n_evil_stage = sum(stage_preds)
            print(f'  {stage_name}: {n_stage:,} sessions, {n_evil_stage:,} evil ({100*n_evil_stage/n_stage:.1f}%)')

    return len(sessions)


def main():
    ap = argparse.ArgumentParser(description='Session-level batch scorer.')
    ap.add_argument('model_path', help='Path to session_xgb_v1.json')
    ap.add_argument('--version', help='Model version string')
    ap.add_argument('--minutes', type=int, default=10, help='Score sessions with activity in last N minutes (default: 10)')
    ap.add_argument('--hours', type=int, default=0, help='Override: score sessions from last N hours')
    args = ap.parse_args()

    mv = args.version or os.path.basename(args.model_path)
    minutes = args.hours * 60 if args.hours > 0 else args.minutes

    ch = Client(CH_HOST, port=CH_PORT)
    score(args.model_path, mv, ch, minutes=minutes)


if __name__ == '__main__':
    main()
