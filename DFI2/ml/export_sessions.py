#!/usr/bin/env python3
"""Export session-level training data from ClickHouse.

Runs on PV1 (clickhouse-client subprocess, --max_threads=0 --max_memory_usage=0).
Pattern: ai-shared/ml/export.py

Usage:
    python3 export_sessions.py all -o /mnt/dfi-data/ml/data/sessions/
    python3 export_sessions.py sessions --db dfi -o /tmp/dfi_sessions.csv
    python3 export_sessions.py timestamps --db dfi -o /tmp/dfi_timestamps.csv
"""
import argparse
import os
import subprocess
import time


CH_HOST = os.environ.get('CH_HOST', 'localhost')
AIO_HOST = os.environ.get('AIO_CH_HOST', '192.168.0.113')  # dfi_dirty/dfi_clean on AIO
OUTPUT_DIR = os.environ.get('ML_OUTPUT_DIR', '/mnt/dfi-data/ml/data/sessions')


def _run_ch(query, output, fmt='CSVWithNames', host=None):
    """Run clickhouse-client subprocess, stream to file."""
    mode = 'wb' if fmt == 'Parquet' else 'w'
    cmd = ['clickhouse-client',
           f'--query={query} FORMAT {fmt}',
           '--max_threads=0', '--max_memory_usage=0']
    if host:
        cmd.append(f'--host={host}')
    with open(output, mode) as fout:
        subprocess.run(cmd, stdout=fout, check=True)


def _count_lines(path):
    with open(path) as f:
        return sum(1 for _ in f) - 1


def _filesize(path):
    size = os.path.getsize(path)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if size < 1024:
            return f'{size:.1f} {unit}'
        size /= 1024
    return f'{size:.1f} PB'


def export_session_features(db, output):
    """Export pre-computed session features from v_session_features."""
    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    t0 = time.time()

    query = f'SELECT * FROM {db}.v_session_features'
    print(f'Exporting {db}.v_session_features ...', flush=True)
    _run_ch(query, output)

    elapsed = time.time() - t0
    n = _count_lines(output)
    print(f'  {n:,} rows, {_filesize(output)}, {elapsed:.1f}s')
    return n


def export_session_timestamps(db, output):
    """Export per-session flow timestamps for IAT computation in Python.

    Groups flow start times into arrays per (src_ip, dst_ip, dst_port).
    """
    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    t0 = time.time()

    query = (
        f'SELECT '
        f'src_ip, dst_ip, dst_port, '
        f'groupArray(first_ts) AS flow_timestamps, '
        f'count() AS n_flows '
        f'FROM {db}.flows '
        f'GROUP BY src_ip, dst_ip, dst_port'
    )
    print(f'Exporting {db} session timestamps ...', flush=True)
    _run_ch(query, output)

    elapsed = time.time() - t0
    n = _count_lines(output)
    print(f'  {n:,} rows, {_filesize(output)}, {elapsed:.1f}s')
    return n


def export_session_labels(output, db='dfi'):
    """Export session-level labels: max(label) per (src_ip, dst_ip, dst_port)."""
    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    t0 = time.time()

    query = (
        f'SELECT '
        f'f.src_ip AS src_ip, f.dst_ip AS dst_ip, f.dst_port AS dst_port, '
        f'max(l.label) AS label, '
        f'avg(l.label_confidence) AS label_confidence, '
        f'count() AS labeled_flow_count '
        f'FROM {db}.flows f '
        f'INNER JOIN {db}.labels l FINAL ON l.flow_id = f.flow_id '
        f'GROUP BY f.src_ip, f.dst_ip, f.dst_port'
    )
    print(f'Exporting {db} session labels ...', flush=True)
    _run_ch(query, output)

    elapsed = time.time() - t0
    n = _count_lines(output)
    print(f'  {n:,} rows, {_filesize(output)}, {elapsed:.1f}s')
    return n


def export_source_stats(db, output):
    """Export source_stats with Merge functions. Pattern: export.py."""
    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    t0 = time.time()

    query = (
        f'SELECT '
        f'src_ip, '
        f'countMerge(flow_count) AS src_flow_count, '
        f'uniqMerge(unique_ports) AS src_unique_ports, '
        f'uniqMerge(unique_protos) AS src_unique_protos, '
        f'uniqMerge(unique_dsts) AS src_unique_dsts, '
        f"dateDiff('minute', minMerge(first_seen), maxMerge(last_seen)) AS src_span_min, "
        f'sumMerge(sum_pps) / greatest(countMerge(flow_count), 1) AS src_avg_pps '
        f'FROM {db}.source_stats GROUP BY src_ip'
    )
    print(f'Exporting {db}.source_stats ...', flush=True)
    _run_ch(query, output)

    elapsed = time.time() - t0
    n = _count_lines(output)
    print(f'  {n:,} rows, {_filesize(output)}, {elapsed:.1f}s')
    return n


def export_dirty_sessions(output):
    """Export dirty session aggregates directly from dfi_dirty.flows."""
    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    t0 = time.time()

    query = (
        'SELECT '
        'src_ip, dst_ip, dst_port, '
        'count() AS sess_flow_count, '
        'sum(bytes_fwd) AS sess_bytes_fwd, '
        'sum(bytes_rev) AS sess_bytes_rev, '
        'sum(pkts_fwd) AS sess_pkts_fwd, '
        'sum(pkts_rev) AS sess_pkts_rev, '
        'if(sum(pkts_fwd) > 0, sum(pkts_rev) / sum(pkts_fwd), 0) AS sess_reply_ratio, '
        "dateDiff('second', min(first_ts), max(first_ts)) AS sess_duration, "
        'if(count() > 0, sum(duration_ms) / count(), 0) AS sess_avg_flow_dur, '
        'max(duration_ms) AS sess_max_flow_dur, '
        'max(bytes_rev) AS sess_max_bytes_rev, '
        'if(count() > 0, (sum(bytes_fwd) + sum(bytes_rev)) / count(), 0) AS sess_avg_bytes_per_flow, '
        'if((sum(bytes_fwd) + sum(bytes_rev)) > 0, '
        '   sum(bytes_rev) / (sum(bytes_fwd) + sum(bytes_rev)), 0) AS sess_payload_ratio, '
        'if(count() > 0, countIf(pkts_rev > 0) / count(), 0) AS sess_bidirectional_ratio, '
        'if(count() > 0, countIf(conn_state = 0) / count(), 0) AS sess_syn_only_ratio, '
        'if(count() > 0, sum(rst_count) / count(), 0) AS sess_rst_ratio, '
        'if(count() > 0, countIf(conn_state = 4) / count(), 0) AS sess_completed_ratio, '
        'if(count() > 0, (sum(syn_count) + sum(fin_count) + sum(rst_count) + sum(psh_count)) / count(), 0) AS sess_avg_tcp_flags, '
        'min(first_ts) AS _first_seen, '
        'max(first_ts) AS _last_seen '
        'FROM dfi_dirty.flows '
        'GROUP BY src_ip, dst_ip, dst_port'
    )
    print('Exporting dfi_dirty session aggregates ...', flush=True)
    _run_ch(query, output, host=AIO_HOST)

    elapsed = time.time() - t0
    n = _count_lines(output)
    print(f'  {n:,} rows, {_filesize(output)}, {elapsed:.1f}s')
    return n


def export_clean_sessions(output):
    """Export clean session aggregates directly from dfi_clean.flows."""
    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    t0 = time.time()

    query = (
        'SELECT '
        'src_ip, dst_ip, dst_port, '
        'count() AS sess_flow_count, '
        'sum(bytes_fwd) AS sess_bytes_fwd, '
        'sum(bytes_rev) AS sess_bytes_rev, '
        'sum(pkts_fwd) AS sess_pkts_fwd, '
        'sum(pkts_rev) AS sess_pkts_rev, '
        'if(sum(pkts_fwd) > 0, sum(pkts_rev) / sum(pkts_fwd), 0) AS sess_reply_ratio, '
        "dateDiff('second', min(first_ts), max(first_ts)) AS sess_duration, "
        'if(count() > 0, sum(duration_ms) / count(), 0) AS sess_avg_flow_dur, '
        'max(duration_ms) AS sess_max_flow_dur, '
        'max(bytes_rev) AS sess_max_bytes_rev, '
        'if(count() > 0, (sum(bytes_fwd) + sum(bytes_rev)) / count(), 0) AS sess_avg_bytes_per_flow, '
        'if((sum(bytes_fwd) + sum(bytes_rev)) > 0, '
        '   sum(bytes_rev) / (sum(bytes_fwd) + sum(bytes_rev)), 0) AS sess_payload_ratio, '
        'if(count() > 0, countIf(pkts_rev > 0) / count(), 0) AS sess_bidirectional_ratio, '
        'if(count() > 0, countIf(conn_state = 0) / count(), 0) AS sess_syn_only_ratio, '
        'if(count() > 0, sum(rst_count) / count(), 0) AS sess_rst_ratio, '
        'if(count() > 0, countIf(conn_state = 4) / count(), 0) AS sess_completed_ratio, '
        'if(count() > 0, (sum(syn_count) + sum(fin_count) + sum(rst_count) + sum(psh_count)) / count(), 0) AS sess_avg_tcp_flags, '
        'min(first_ts) AS _first_seen, '
        'max(first_ts) AS _last_seen '
        'FROM dfi_clean.flows '
        'GROUP BY src_ip, dst_ip, dst_port'
    )
    print('Exporting dfi_clean session aggregates ...', flush=True)
    _run_ch(query, output, host=AIO_HOST)

    elapsed = time.time() - t0
    n = _count_lines(output)
    print(f'  {n:,} rows, {_filesize(output)}, {elapsed:.1f}s')
    return n


def export_dirty_timestamps(output):
    """Export dirty per-session flow timestamps for IAT."""
    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    t0 = time.time()

    query = (
        'SELECT '
        'src_ip, dst_ip, dst_port, '
        'groupArray(first_ts) AS flow_timestamps, '
        'count() AS n_flows '
        'FROM dfi_dirty.flows '
        'GROUP BY src_ip, dst_ip, dst_port'
    )
    print('Exporting dfi_dirty session timestamps ...', flush=True)
    _run_ch(query, output, host=AIO_HOST)

    elapsed = time.time() - t0
    n = _count_lines(output)
    print(f'  {n:,} rows, {_filesize(output)}, {elapsed:.1f}s')
    return n


def export_clean_timestamps(output):
    """Export clean per-session flow timestamps for IAT."""
    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    t0 = time.time()

    query = (
        'SELECT '
        'src_ip, dst_ip, dst_port, '
        'groupArray(first_ts) AS flow_timestamps, '
        'count() AS n_flows '
        'FROM dfi_clean.flows '
        'GROUP BY src_ip, dst_ip, dst_port'
    )
    print('Exporting dfi_clean session timestamps ...', flush=True)
    _run_ch(query, output, host=AIO_HOST)

    elapsed = time.time() - t0
    n = _count_lines(output)
    print(f'  {n:,} rows, {_filesize(output)}, {elapsed:.1f}s')
    return n


def export_all(output_dir):
    """Export everything needed for session model training."""
    os.makedirs(output_dir, exist_ok=True)
    t0 = time.time()

    # DFI labeled sessions (from v_session_features view via session_stats MV)
    export_session_features('dfi', os.path.join(output_dir, 'dfi_session_features.csv'))
    export_session_timestamps('dfi', os.path.join(output_dir, 'dfi_session_timestamps.csv'))
    export_session_labels(os.path.join(output_dir, 'dfi_session_labels.csv'))
    export_source_stats('dfi', os.path.join(output_dir, 'dfi_source_stats.csv'))

    # Dirty sessions (direct GROUP BY — no session_stats MV on dfi_dirty)
    export_dirty_sessions(os.path.join(output_dir, 'dirty_sessions.csv'))
    export_dirty_timestamps(os.path.join(output_dir, 'dirty_timestamps.csv'))

    # Clean sessions
    export_clean_sessions(os.path.join(output_dir, 'clean_sessions.csv'))
    export_clean_timestamps(os.path.join(output_dir, 'clean_timestamps.csv'))

    elapsed = time.time() - t0
    print(f'\nAll session exports done in {elapsed:.1f}s → {output_dir}')


def main():
    ap = argparse.ArgumentParser(description='Export session-level training data from ClickHouse.')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p_sess = sub.add_parser('sessions', help='Export session features from v_session_features')
    p_sess.add_argument('--db', default='dfi')
    p_sess.add_argument('-o', '--output', help='Output CSV path')

    p_ts = sub.add_parser('timestamps', help='Export per-session flow timestamps')
    p_ts.add_argument('--db', default='dfi')
    p_ts.add_argument('-o', '--output', help='Output CSV path')

    p_lbl = sub.add_parser('labels', help='Export session-level labels')
    p_lbl.add_argument('--db', default='dfi')
    p_lbl.add_argument('-o', '--output', help='Output CSV path')

    p_src = sub.add_parser('source-stats', help='Export source_stats')
    p_src.add_argument('--db', default='dfi')
    p_src.add_argument('-o', '--output', help='Output CSV path')

    p_dirty = sub.add_parser('dirty', help='Export dirty session aggregates')
    p_dirty.add_argument('-o', '--output', help='Output CSV path')

    p_clean = sub.add_parser('clean', help='Export clean session aggregates')
    p_clean.add_argument('-o', '--output', help='Output CSV path')

    p_all = sub.add_parser('all', help='Export everything for session model training')
    p_all.add_argument('-o', '--output', help='Output directory')

    args = ap.parse_args()

    if args.cmd == 'sessions':
        out = args.output or os.path.join(OUTPUT_DIR, f'{args.db}_session_features.csv')
        export_session_features(args.db, out)
    elif args.cmd == 'timestamps':
        out = args.output or os.path.join(OUTPUT_DIR, f'{args.db}_session_timestamps.csv')
        export_session_timestamps(args.db, out)
    elif args.cmd == 'labels':
        out = args.output or os.path.join(OUTPUT_DIR, f'{args.db}_session_labels.csv')
        export_session_labels(out, db=args.db)
    elif args.cmd == 'source-stats':
        out = args.output or os.path.join(OUTPUT_DIR, f'{args.db}_source_stats.csv')
        export_source_stats(args.db, out)
    elif args.cmd == 'dirty':
        out = args.output or os.path.join(OUTPUT_DIR, 'dirty_sessions.csv')
        export_dirty_sessions(out)
    elif args.cmd == 'clean':
        out = args.output or os.path.join(OUTPUT_DIR, 'clean_sessions.csv')
        export_clean_sessions(out)
    elif args.cmd == 'all':
        out = args.output or OUTPUT_DIR
        export_all(out)


if __name__ == '__main__':
    main()
