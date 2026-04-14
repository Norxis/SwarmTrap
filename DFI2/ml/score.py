#!/usr/bin/env python3
import argparse
import os

import numpy as np
from clickhouse_driver import Client

CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))
BATCH_SIZE = 200000
SEQ_LEN = 128

STATIC_COLS = [
    'dst_port', 'ip_proto', 'app_proto', 'pkts_fwd', 'pkts_rev', 'bytes_fwd', 'bytes_rev',
    'bytes_per_pkt_fwd', 'bytes_per_pkt_rev', 'pkt_ratio', 'byte_ratio', 'rtt_ms', 'n_events',
    'entropy_first', 'entropy_fwd_mean', 'entropy_rev_mean', 'printable_frac', 'null_frac', 'byte_std', 'high_entropy_frac', 'payload_len_first',
    'ja3_freq', 'tls_version', 'tls_cipher_count', 'tls_ext_count', 'tls_has_sni', 'hassh_freq', 'ssh_kex_count',
    'http_method', 'http_uri_len', 'http_header_count', 'http_ua_freq', 'http_has_body', 'http_status',
    'dns_qtype', 'dns_qname_len', 'src_flow_count', 'src_unique_ports', 'src_unique_protos', 'src_unique_dsts', 'src_span_min', 'src_avg_pps',
]


def _flow_meta_map(ch: Client, flow_ids: list[str]) -> dict:
    if not flow_ids:
        return {}
    rows = ch.execute(
        'SELECT flow_id, src_ip, dst_ip, dst_port, first_ts FROM dfi.flows WHERE flow_id IN %(fids)s',
        {'fids': flow_ids},
        settings={'max_query_size': 50000000},
    )
    return {
        r[0]: {
            'src_ip': r[1],
            'dst_ip': r[2],
            'dst_port': int(r[3]),
            'first_ts': r[4],
        }
        for r in rows
    }


def score_xgb(ch: Client, model_path: str, model_version: str, hours: int = 0):
    import pandas as pd
    import xgboost as xgb

    model = xgb.Booster({'nthread': 80})
    model.load_model(model_path)

    time_filter = ''
    if hours > 0:
        time_filter = f'AND f.first_ts >= now() - INTERVAL {hours} HOUR'

    meta = ch.execute('SELECT * FROM dfi.v_xgb LIMIT 0', with_column_types=True)
    cols = [c[0] for c in meta[1]]
    # Rename ClickHouse aliased columns (f.flow_id → flow_id, f.dst_port → dst_port)
    cols = [c.replace('f.', '') for c in cols]
    id_meta = ['flow_id', 'session_key', 'actor_id', 'label', 'label_confidence', 'evidence_mask', 'evidence_detail']
    feat_cols = [c for c in cols if c not in id_meta]

    # Get unscored flow_ids first using ANTI JOIN (fast), then batch-fetch features
    unscored_ids = ch.execute(
        f"""
        SELECT f.flow_id
        FROM dfi.flows f
        INNER JOIN dfi.labels l ON l.flow_id = f.flow_id
        LEFT ANTI JOIN dfi.model_predictions p
            ON p.flow_id = f.flow_id AND p.model_name = 'xgb_v7' AND p.model_version = %(mv)s
        WHERE l.label IN (1, 2, 3, 5) {time_filter}
        """,
        {'mv': model_version},
    )
    all_fids = [r[0] for r in unscored_ids]
    print(f'Unscored flows: {len(all_fids)}', flush=True)

    total = 0
    for batch_start in range(0, len(all_fids), BATCH_SIZE):
        batch_fids = all_fids[batch_start:batch_start + BATCH_SIZE]
        rows = ch.execute(
            'SELECT * FROM dfi.v_xgb WHERE `f.flow_id` IN %(fids)s',
            {'fids': batch_fids},
            settings={'max_query_size': 50000000},
        )
        if not rows:
            continue

        df = pd.DataFrame(rows, columns=cols)
        # Model may have been trained with _rn column from balanced export — add dummy if missing
        model_feats = model.feature_names
        for mf in model_feats:
            if mf not in df.columns:
                df[mf] = 0
        dmat = xgb.DMatrix(df[model_feats].values.astype(np.float32), feature_names=model_feats, nthread=80)
        # binary:logistic returns P(class=1) as 1D array
        prob_attack = model.predict(dmat)
        preds = (prob_attack > 0.5).astype(int)
        confs = np.where(preds == 1, prob_attack, 1.0 - prob_attack)
        flow_ids = df['flow_id'].tolist()
        meta_map = _flow_meta_map(ch, flow_ids)

        pred_rows = []
        for i in range(len(df)):
            fid = df.iloc[i]['flow_id']
            fm = meta_map.get(fid, {})
            pred_rows.append(
                {
                    'flow_id': fid,
                    'src_ip': fm.get('src_ip', '0.0.0.0'),
                    'dst_ip': fm.get('dst_ip', '0.0.0.0'),
                    'dst_port': int(fm.get('dst_port', df.iloc[i]['dst_port'])),
                    'flow_first_ts': fm.get('first_ts'),
                    'model_name': 'xgb_v7',
                    'model_version': model_version,
                    'label': int(preds[i]),
                    'confidence': float(confs[i]),
                    'class_probs': [float(1.0 - prob_attack[i]), float(prob_attack[i])],
                }
            )
        cols_insert = 'flow_id, src_ip, dst_ip, dst_port, flow_first_ts, model_name, model_version, label, confidence, class_probs'
        ch.execute(f'INSERT INTO dfi.model_predictions_buffer ({cols_insert}) VALUES', pred_rows)
        total += len(pred_rows)
        print(f'  Scored {total}/{len(all_fids)} ({100*total/len(all_fids):.1f}%)', flush=True)
    return total


def score_cnn(ch: Client, model_path: str, model_version: str, hours: int = 0):
    import torch

    try:
        from .train_cnn import DFI_CNN
    except ImportError:
        from train_cnn import DFI_CNN

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model = DFI_CNN()
    model.load_state_dict(torch.load(model_path, map_location=device))
    model.to(device)
    model.eval()

    where = ''
    if hours > 0:
        where = f'AND f.first_ts >= now() - INTERVAL {hours} HOUR'

    flow_ids = ch.execute(
        f"""
        SELECT DISTINCT f.flow_id
        FROM dfi.flows f
        INNER JOIN dfi.packets p ON p.flow_id = f.flow_id
        WHERE f.flow_id NOT IN (
            SELECT flow_id FROM dfi.model_predictions
            WHERE model_name='cnn_v1' AND model_version=%(mv)s
            UNION ALL
            SELECT flow_id FROM dfi.model_predictions_buffer
            WHERE model_name='cnn_v1' AND model_version=%(mv)s
        ) {where}
        LIMIT {BATCH_SIZE}
        """,
        {'mv': model_version},
    )
    if not flow_ids:
        return 0
    fids = [r[0] for r in flow_ids]

    seq_data = ch.execute(
        '''SELECT flow_id,
                  groupArray(128)(size_dir_token),
                  groupArray(128)(flag_token),
                  groupArray(128)(iat_log_ms_bin),
                  groupArray(128)(iat_rtt_bin),
                  groupArray(128)(entropy_bin)
           FROM (SELECT * FROM dfi.packets WHERE flow_id IN %(fids)s ORDER BY flow_id,seq_idx)
           GROUP BY flow_id''',
        {'fids': fids},
    )
    static_rows = ch.execute('SELECT * FROM dfi.v_xgb WHERE flow_id IN %(fids)s', {'fids': fids})
    meta = ch.execute('SELECT * FROM dfi.v_xgb LIMIT 0', with_column_types=True)
    cols = [c[0] for c in meta[1]]

    seq_map = {}
    for row in seq_data:
        def pad(a):
            a = list(a)
            a += [0] * (SEQ_LEN - len(a))
            return np.array(a[:SEQ_LEN])
        raw_size = pad(row[1])
        seq_map[row[0]] = {'size': np.where(raw_size == 0, 0, raw_size + 12), 'flag': pad(row[2]), 'iat': pad(row[3]), 'rtt': pad(row[4]), 'ent': pad(row[5])}

    static_map = {dict(zip(cols, r))['flow_id']: dict(zip(cols, r)) for r in static_rows}
    flow_meta = _flow_meta_map(ch, fids)

    # Build batched tensors for all valid flows
    valid_fids = [fid for fid in fids if fid in seq_map and fid in static_map]
    if not valid_fids:
        return 0

    CNN_BATCH = 256
    pred_rows = []
    with torch.no_grad():
        for batch_start in range(0, len(valid_fids), CNN_BATCH):
            batch_fids = valid_fids[batch_start:batch_start + CNN_BATCH]
            size_batch, flag_batch, iat_batch, rtt_batch, ent_batch, stat_batch = [], [], [], [], [], []

            for fid in batch_fids:
                s = seq_map[fid]
                st_row = static_map[fid]
                size_batch.append(s['size'])
                flag_batch.append(s['flag'])
                iat_batch.append(s['iat'])
                rtt_batch.append(s['rtt'])
                ent_batch.append(s['ent'])
                stat_batch.append([float(st_row.get(c, 0) or 0) for c in STATIC_COLS])

            size_t = torch.tensor(np.array(size_batch), dtype=torch.long).to(device)
            flag_t = torch.tensor(np.array(flag_batch), dtype=torch.long).to(device)
            iat_t = torch.tensor(np.array(iat_batch), dtype=torch.long).to(device)
            rtt_t = torch.tensor(np.array(rtt_batch), dtype=torch.long).to(device)
            ent_t = torch.tensor(np.array(ent_batch), dtype=torch.long).to(device)
            stat_t = torch.tensor(np.array(stat_batch, dtype=np.float32), dtype=torch.float32).to(device)

            logits = model(size_t, flag_t, iat_t, rtt_t, ent_t, stat_t)
            probs = torch.softmax(logits, dim=1).cpu().numpy()
            preds = np.argmax(probs, axis=1)
            confs = np.max(probs, axis=1)

            for i, fid in enumerate(batch_fids):
                st_row = static_map[fid]
                pred_rows.append(
                    {
                        'flow_id': fid,
                        'src_ip': flow_meta.get(fid, {}).get('src_ip', '0.0.0.0'),
                        'dst_ip': flow_meta.get(fid, {}).get('dst_ip', '0.0.0.0'),
                        'dst_port': int(flow_meta.get(fid, {}).get('dst_port', st_row.get('dst_port', 0) or 0)),
                        'flow_first_ts': flow_meta.get(fid, {}).get('first_ts'),
                        'model_name': 'cnn_v1',
                        'model_version': model_version,
                        'label': int(preds[i]),
                        'confidence': float(confs[i]),
                        'class_probs': [float(x) for x in probs[i].tolist()],
                    }
                )

    if pred_rows:
        ch.execute('INSERT INTO dfi.model_predictions_buffer VALUES', pred_rows)
    return len(pred_rows)


def evidence_report(ch: Client, model_name: str):
    """Report predictions that contradict hard evidence (evidence_mask > 0)."""
    label_names = {1: 'KNOCK', 2: 'BRUTE', 3: 'EXPLOIT', 5: 'NORM'}

    # Hard-evidence attacks predicted as NORM (false negatives)
    fn_rows = ch.execute(
        """
        SELECT l.label, count(), round(avg(p.confidence), 4), round(avg(l.label_confidence), 4)
        FROM dfi.model_predictions p
        INNER JOIN dfi.labels l ON l.flow_id = p.flow_id
        WHERE p.model_name = %(mn)s AND p.label = 0
            AND l.label IN (1, 2, 3) AND l.evidence_mask > 0
        GROUP BY l.label ORDER BY l.label
        """,
        {'mn': model_name},
    )

    # Norm predicted as ATTACK (false positives)
    fp_rows = ch.execute(
        """
        SELECT count(), round(avg(p.confidence), 4)
        FROM dfi.model_predictions p
        INNER JOIN dfi.labels l ON l.flow_id = p.flow_id
        WHERE p.model_name = %(mn)s AND p.label = 1 AND l.label = 5
        """,
        {'mn': model_name},
    )

    # Total scored
    total = ch.execute(
        'SELECT count() FROM dfi.model_predictions WHERE model_name = %(mn)s',
        {'mn': model_name},
    )[0][0]

    print(f'\n=== Evidence Report ({model_name}, {total} scored) ===')

    total_fn = 0
    if fn_rows:
        print('Hard-evidence attacks predicted NORM (FN):')
        for label, cnt, avg_conf, avg_lbl_conf in fn_rows:
            name = label_names.get(label, str(label))
            print(f'  {name}: {cnt} (model_conf={avg_conf}, label_conf={avg_lbl_conf})')
            total_fn += cnt
    else:
        print('Hard-evidence FN: 0')

    fp_cnt = fp_rows[0][0] if fp_rows else 0
    fp_conf = fp_rows[0][1] if fp_rows and fp_rows[0][1] else 0

    print(f'Norm predicted ATTACK (FP): {fp_cnt} (avg_conf={fp_conf})')
    print(f'Total evidence mismatches: {total_fn + fp_cnt} ({100 * (total_fn + fp_cnt) / total:.3f}% of scored)')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('model', choices=['xgb', 'cnn'])
    ap.add_argument('model_path')
    ap.add_argument('--version')
    ap.add_argument('--hours', type=int, default=0)
    args = ap.parse_args()

    mv = args.version or os.path.basename(args.model_path)
    ch = Client(CH_HOST, port=CH_PORT)
    if args.model == 'xgb':
        n = score_xgb(ch, args.model_path, mv, args.hours)
        mn = 'xgb_v7'
    else:
        n = score_cnn(ch, args.model_path, mv, args.hours)
        mn = 'cnn_v1'
    print(f'Scored: {n}')
    evidence_report(ch, mn)


if __name__ == '__main__':
    main()
