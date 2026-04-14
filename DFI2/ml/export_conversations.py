#!/usr/bin/env python3
"""Raw dump export from ClickHouse conversation tables.

Usage:
    python3 export_conversations.py conversations -o /tmp/conv/conversations.csv
    python3 export_conversations.py turns -o /tmp/conv/turns.csv
    python3 export_conversations.py labels -o /tmp/conv/labels.csv
    python3 export_conversations.py all -o /tmp/conv/
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


def export_conversations(output):
    """Raw dump dfi.conversations table."""
    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    t0 = time.time()

    query = 'SELECT * FROM dfi.conversations'
    print('Exporting dfi.conversations ...', flush=True)
    _run_ch(query, output)

    elapsed = time.time() - t0
    n = _count_lines(output)
    print(f'  {n:,} rows, {_filesize(output)}, {elapsed:.1f}s')
    return n


def export_turns(output):
    """Raw dump dfi.conversation_turns table."""
    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    t0 = time.time()

    query = 'SELECT * FROM dfi.conversation_turns ORDER BY conversation_id, turn_idx'
    print('Exporting dfi.conversation_turns ...', flush=True)
    _run_ch(query, output)

    elapsed = time.time() - t0
    n = _count_lines(output)
    print(f'  {n:,} rows, {_filesize(output)}, {elapsed:.1f}s')
    return n


def export_labels(output):
    """Raw dump dfi.conversation_labels table."""
    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    t0 = time.time()

    query = 'SELECT * FROM dfi.conversation_labels'
    print('Exporting dfi.conversation_labels ...', flush=True)
    _run_ch(query, output)

    elapsed = time.time() - t0
    n = _count_lines(output)
    print(f'  {n:,} rows, {_filesize(output)}, {elapsed:.1f}s')
    return n


def export_all(output_dir):
    """Export conversations + turns + labels to a directory."""
    os.makedirs(output_dir, exist_ok=True)
    t0 = time.time()

    export_conversations(os.path.join(output_dir, 'conversations.csv'))
    export_turns(os.path.join(output_dir, 'turns.csv'))
    export_labels(os.path.join(output_dir, 'labels.csv'))

    elapsed = time.time() - t0
    print(f'\nAll conversation exports done in {elapsed:.1f}s → {output_dir}')


def main():
    ap = argparse.ArgumentParser(description='Raw dump export from ClickHouse conversation tables.')
    sub = ap.add_subparsers(dest='cmd', required=True)

    # conversations
    p_conv = sub.add_parser('conversations', help='Raw dump conversations table')
    p_conv.add_argument('-o', '--output', help='Output CSV path')

    # turns
    p_turns = sub.add_parser('turns', help='Raw dump conversation_turns table')
    p_turns.add_argument('-o', '--output', help='Output CSV path')

    # labels
    p_labels = sub.add_parser('labels', help='Raw dump conversation_labels table')
    p_labels.add_argument('-o', '--output', help='Output CSV path')

    # all
    p_all = sub.add_parser('all', help='Export conversations + turns + labels')
    p_all.add_argument('-o', '--output', help='Output directory')

    args = ap.parse_args()

    if args.cmd == 'conversations':
        out = args.output or os.path.join(OUTPUT_DIR, 'conversations.csv')
        export_conversations(out)

    elif args.cmd == 'turns':
        out = args.output or os.path.join(OUTPUT_DIR, 'conversation_turns.csv')
        export_turns(out)

    elif args.cmd == 'labels':
        out = args.output or os.path.join(OUTPUT_DIR, 'conversation_labels.csv')
        export_labels(out)

    elif args.cmd == 'all':
        out = args.output or os.path.join(OUTPUT_DIR, 'conversations')
        export_all(out)


if __name__ == '__main__':
    main()
