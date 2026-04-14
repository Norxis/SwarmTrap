#!/usr/bin/env python3
"""Raw dump export from ClickHouse flows tables.

NEVER use v_xgb for export — it's a VIEW with GROUP BY + source_stats JOIN
that doubles memory and causes OOM. NEVER use arrayElement() in CH.

Export raw flows CSV (arrays as [1,2,3,...] strings).
Expand arrays + compute derived features + join src_* in Python on Test.

Usage:
    python3 export.py flows --db dfi_clean -o /tmp/clean.csv
    python3 export.py flows --db dfi_dirty -o /tmp/dirty.csv
    python3 export.py flows --db dfi --labeled -o /tmp/attack.csv
    python3 export.py flows --db dfi --labeled --labels 0,5 -o /tmp/norm.csv
    python3 export.py labels -o /tmp/labels.csv
    python3 export.py source-stats --db dfi_clean -o /tmp/clean_src.csv
    python3 export.py all --db dfi_clean -o /tmp/dfi_clean/
"""
import argparse
import os
import subprocess
import time


CH_HOST = os.environ.get('CH_HOST', 'localhost')
OUTPUT_DIR = os.environ.get('ML_OUTPUT_DIR', '/mnt/dfi-data/ml/data')


def _run_ch(query, output, fmt='CSVWithNames'):
    """Run clickhouse-client subprocess, stream to file."""
    mode = 'wb' if fmt == 'Parquet' else 'w'
    with open(output, mode) as fout:
        subprocess.run(
            ['clickhouse-client',
             f'--query={query} FORMAT {fmt}',
             '--max_threads=0', '--max_memory_usage=0'],
            stdout=fout, check=True,
        )


def _count_lines(path):
    """Count lines in file (subtract 1 for header)."""
    with open(path) as f:
        return sum(1 for _ in f) - 1


def _filesize(path):
    """Human-readable file size."""
    size = os.path.getsize(path)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if size < 1024:
            return f'{size:.1f} {unit}'
        size /= 1024
    return f'{size:.1f} PB'


def export_flows(db, output, limit=0, d2_only=True, labeled=False, labels=None):
    """Raw dump SELECT * FROM {db}.flows.

    Arrays (pkt_size_dir, pkt_flag, etc.) export as [1,2,3,...] strings.
    Expand in Python later.

    Args:
        db: Database name (dfi, dfi_dirty, dfi_clean)
        output: Output CSV path
        limit: Max rows (0=all)
        d2_only: Filter length(pkt_size_dir) > 0
        labeled: Only export flows that have labels (dfi only)
        labels: Comma-separated label codes to filter (e.g. '1,2,3')
    """
    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    t0 = time.time()

    conds = []
    if d2_only:
        conds.append('length(pkt_size_dir) > 0')
    if labeled:
        label_filter = ''
        if labels:
            label_filter = f' WHERE label IN ({labels})'
        conds.append(f'flow_id IN (SELECT flow_id FROM {db}.labels{label_filter})')

    where = f" WHERE {' AND '.join(conds)}" if conds else ''
    limit_clause = f' LIMIT {limit}' if limit > 0 else ''

    query = f'SELECT * FROM {db}.flows{where}{limit_clause}'
    print(f'Exporting {db}.flows ...', flush=True)
    _run_ch(query, output)

    elapsed = time.time() - t0
    n = _count_lines(output)
    print(f'  {n:,} rows, {_filesize(output)}, {elapsed:.1f}s')
    return n


def export_labels(output, db='dfi'):
    """Raw dump labels table."""
    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    t0 = time.time()

    query = f'SELECT * FROM {db}.labels'
    print(f'Exporting {db}.labels ...', flush=True)
    _run_ch(query, output)

    elapsed = time.time() - t0
    n = _count_lines(output)
    print(f'  {n:,} rows, {_filesize(output)}, {elapsed:.1f}s')
    return n


def export_source_stats(db, output):
    """Export source_stats with Merge functions (AggregatingMergeTree).

    Small table (~1M rows). No JOINs.
    """
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


def export_all(db, output_dir, limit=0, d2_only=True, labeled=False, labels=None):
    """Export flows + source_stats (+ labels if dfi) to a directory."""
    os.makedirs(output_dir, exist_ok=True)
    t0 = time.time()

    flows_path = os.path.join(output_dir, f'{db}_flows.csv')
    export_flows(db, flows_path, limit=limit, d2_only=d2_only,
                 labeled=labeled, labels=labels)

    src_path = os.path.join(output_dir, f'{db}_source_stats.csv')
    export_source_stats(db, src_path)

    if db == 'dfi':
        labels_path = os.path.join(output_dir, f'{db}_labels.csv')
        export_labels(labels_path, db=db)

    elapsed = time.time() - t0
    print(f'\nAll exports for {db} done in {elapsed:.1f}s → {output_dir}')


def main():
    ap = argparse.ArgumentParser(description='Raw dump export from ClickHouse flows.')
    sub = ap.add_subparsers(dest='cmd', required=True)

    # flows
    p_flows = sub.add_parser('flows', help='Raw dump flows table')
    p_flows.add_argument('--db', default='dfi', help='Database (dfi, dfi_dirty, dfi_clean)')
    p_flows.add_argument('-o', '--output', help='Output CSV path')
    p_flows.add_argument('--limit', type=int, default=0, help='Max rows (0=all)')
    p_flows.add_argument('--no-d2-filter', action='store_true', help='Include flows without pkt arrays')
    p_flows.add_argument('--labeled', action='store_true', help='Only labeled flows (dfi only)')
    p_flows.add_argument('--labels', type=str, default=None, help='Label codes to filter (e.g. 1,2,3)')

    # labels
    p_labels = sub.add_parser('labels', help='Raw dump labels table')
    p_labels.add_argument('--db', default='dfi')
    p_labels.add_argument('-o', '--output', help='Output CSV path')

    # source-stats
    p_ss = sub.add_parser('source-stats', help='Export source_stats with Merge functions')
    p_ss.add_argument('--db', default='dfi', help='Database')
    p_ss.add_argument('-o', '--output', help='Output CSV path')

    # all
    p_all = sub.add_parser('all', help='Export flows + source_stats (+ labels if dfi)')
    p_all.add_argument('--db', default='dfi', help='Database')
    p_all.add_argument('-o', '--output', help='Output directory')
    p_all.add_argument('--limit', type=int, default=0, help='Max rows for flows (0=all)')
    p_all.add_argument('--no-d2-filter', action='store_true')
    p_all.add_argument('--labeled', action='store_true')
    p_all.add_argument('--labels', type=str, default=None)

    args = ap.parse_args()

    if args.cmd == 'flows':
        out = args.output or os.path.join(OUTPUT_DIR, f'{args.db}_flows.csv')
        export_flows(args.db, out, limit=args.limit,
                     d2_only=not args.no_d2_filter,
                     labeled=args.labeled, labels=args.labels)

    elif args.cmd == 'labels':
        out = args.output or os.path.join(OUTPUT_DIR, f'{args.db}_labels.csv')
        export_labels(out, db=args.db)

    elif args.cmd == 'source-stats':
        out = args.output or os.path.join(OUTPUT_DIR, f'{args.db}_source_stats.csv')
        export_source_stats(args.db, out)

    elif args.cmd == 'all':
        out = args.output or os.path.join(OUTPUT_DIR, args.db)
        export_all(args.db, out, limit=args.limit,
                   d2_only=not getattr(args, 'no_d2_filter', False),
                   labeled=args.labeled, labels=args.labels)


if __name__ == '__main__':
    main()
