#!/usr/bin/env python3
"""Export ip_capture_d2 training data from PV1 ClickHouse.

Copied from proven export.py — same clickhouse-client subprocess pattern.
Exports ATTACK and CLEAN groups separately for balanced training.

Usage (run on PV1):
    python3 export_d2.py attack -o /tmp/d2_attack.csv
    python3 export_d2.py clean -o /tmp/d2_clean.csv
    python3 export_d2.py all -o /tmp/d2/
"""
import argparse
import os
import subprocess
import time

CH_HOST = os.environ.get('CH_HOST', 'localhost')
OUTPUT_DIR = os.environ.get('ML_OUTPUT_DIR', '/mnt/dfi-data/ml/data')

# Clean groups (DIS_FP_* + CLN + RB)
CLEAN_GROUPS = (
    'CLN', 'RB',
    'DIS_FP_HTTP', 'DIS_FP_UNK', 'DIS_FP_RDP', 'DIS_FP_SQL',
    'DIS_FP_SSH', 'DIS_FP_MAIL', 'DIS_FP_SMB', 'DIS_FP_MONGODB', 'DIS_FP_VNC',
)

# Exclude from training (ambiguous)
EXCLUDE_GROUPS = ('DNS_NOEVD',)


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
    with open(path) as f:
        return sum(1 for _ in f) - 1


def _filesize(path):
    size = os.path.getsize(path)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if size < 1024:
            return f'{size:.1f} {unit}'
        size /= 1024
    return f'{size:.1f} PB'


def export_attack(output, limit=0):
    """Export ATTACK flows — everything except clean and excluded groups."""
    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    t0 = time.time()

    clean_list = ','.join(f"'{g}'" for g in CLEAN_GROUPS)
    excl_list = ','.join(f"'{g}'" for g in EXCLUDE_GROUPS)

    query = (
        f"SELECT * FROM dfi.ip_capture_d2 "
        f"WHERE discrepancy_type NOT IN ({clean_list}) "
        f"AND discrepancy_type NOT IN ({excl_list})"
    )
    if limit > 0:
        query += f" LIMIT {limit}"

    print(f'Exporting ATTACK flows from ip_capture_d2 ...', flush=True)
    _run_ch(query, output)

    elapsed = time.time() - t0
    n = _count_lines(output)
    print(f'  ATTACK: {n:,} rows, {_filesize(output)}, {elapsed:.1f}s')
    return n


def export_clean(output, limit=0):
    """Export CLEAN flows — CLN + all DIS_FP_* + RB."""
    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    t0 = time.time()

    clean_list = ','.join(f"'{g}'" for g in CLEAN_GROUPS)
    query = f"SELECT * FROM dfi.ip_capture_d2 WHERE discrepancy_type IN ({clean_list})"
    if limit > 0:
        query += f" LIMIT {limit}"

    print(f'Exporting CLEAN flows from ip_capture_d2 ...', flush=True)
    _run_ch(query, output)

    elapsed = time.time() - t0
    n = _count_lines(output)
    print(f'  CLEAN: {n:,} rows, {_filesize(output)}, {elapsed:.1f}s')
    return n


def export_all(output_dir, limit=0):
    """Export both ATTACK and CLEAN to a directory."""
    os.makedirs(output_dir, exist_ok=True)
    t0 = time.time()

    atk_path = os.path.join(output_dir, 'd2_attack.csv')
    cln_path = os.path.join(output_dir, 'd2_clean.csv')
    n_atk = export_attack(atk_path, limit=limit)
    n_cln = export_clean(cln_path, limit=limit)

    elapsed = time.time() - t0
    print(f'\nAll exports done in {elapsed:.1f}s → {output_dir}')
    print(f'  ATTACK: {n_atk:,}  CLEAN: {n_cln:,}  TOTAL: {n_atk + n_cln:,}')


def main():
    ap = argparse.ArgumentParser(description='Export D2 training data from ip_capture_d2')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p_atk = sub.add_parser('attack', help='Export attack flows')
    p_atk.add_argument('-o', '--output', default=os.path.join(OUTPUT_DIR, 'd2_attack.csv'))
    p_atk.add_argument('--limit', type=int, default=0)

    p_cln = sub.add_parser('clean', help='Export clean flows')
    p_cln.add_argument('-o', '--output', default=os.path.join(OUTPUT_DIR, 'd2_clean.csv'))
    p_cln.add_argument('--limit', type=int, default=0)

    p_all = sub.add_parser('all', help='Export both attack + clean')
    p_all.add_argument('-o', '--output', default=os.path.join(OUTPUT_DIR, 'd2'))
    p_all.add_argument('--limit', type=int, default=0)

    args = ap.parse_args()

    if args.cmd == 'attack':
        export_attack(args.output, limit=args.limit)
    elif args.cmd == 'clean':
        export_clean(args.output, limit=args.limit)
    elif args.cmd == 'all':
        export_all(args.output, limit=args.limit)


if __name__ == '__main__':
    main()
