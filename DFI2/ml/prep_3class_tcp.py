#!/usr/bin/env python3
"""Prep 3-class XGB: TCP-only, ingress-only (vlan 100 or 0). Balanced. Parquet output.

Uses polars for fast loading and writing — ~10x faster than csv module.

Usage:
    python3 prep_3class_tcp.py /nvme0n1-disk/ml/data -o /nvme0n1-disk/ml/data/training_3class_tcp.parquet
"""
import argparse
import os
import time

import polars as pl

DATA_DIR = '/nvme0n1-disk/ml/data'

SKIP = {
    'flow_id', 'session_key', 'src_ip', 'dst_ip', 'first_ts', 'last_ts',
    'ingested_at', 'capture_depth', 'vlan_id', 'src_port',
    'pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy',
    'size_dir_arr', 'tcp_flags_arr', 'iat_log_ms_arr', 'iat_rtt_bin_arr', 'entropy_bin_arr',
    'label', 'label_confidence',
}

SOURCES = [
    ('new_recon.csv',      0),
    ('new_knock.csv',      1),
    ('new_brute.csv',      1),
    ('new_exploit.csv',    1),
    ('clean_vlan100.csv',  2),
]

CLASS_NAMES = {0: 'RECON', 1: 'ATTACK', 2: 'CLEAN'}


def load_tcp_ingress(filepath, label):
    """Load CSV, filter TCP + ingress, assign label."""
    t0 = time.time()
    df = pl.read_csv(filepath, null_values=[r'\N', 'NULL', ''], infer_schema_length=50000, ignore_errors=True)
    n_raw = len(df)
    # Filter TCP only + ingress only
    df = df.filter(
        (pl.col('ip_proto') == 6) & (pl.col('vlan_id') != 101)
    )
    # Add label (Float64 to match cast above)
    df = df.with_columns([
        pl.lit(float(label)).alias('label'),
        pl.lit(1.0).alias('label_confidence'),
    ])
    print(f'  {os.path.basename(filepath)}: {n_raw:,} → {len(df):,} TCP ingress → label {label} ({time.time()-t0:.0f}s)', flush=True)
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('data_dir', nargs='?', default=DATA_DIR)
    ap.add_argument('-o', '--output', default=os.path.join(DATA_DIR, 'training_3class_tcp.parquet'))
    args = ap.parse_args()
    data = args.data_dir
    t0 = time.time()

    # Load all sources
    print('=== Loading TCP ingress flows ===', flush=True)
    class_dfs = {0: [], 1: [], 2: []}
    for src_file, label in SOURCES:
        path = os.path.join(data, src_file)
        if not os.path.exists(path):
            print(f'  SKIP {src_file} (not found)', flush=True)
            continue
        df = load_tcp_ingress(path, label)
        class_dfs[label].append(df)

    # Cast ALL non-string feature cols to Float64 before concat
    # Fixes Int64/Float64/String mismatches across files (proven fix from CNN prep)
    KEEP_STRING = {'actor_id', 'flow_id', 'session_key', 'src_ip', 'dst_ip',
                   'first_ts', 'last_ts', 'ingested_at',
                   'pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy',
                   'size_dir_arr', 'tcp_flags_arr', 'iat_log_ms_arr', 'iat_rtt_bin_arr', 'entropy_bin_arr'}
    for label in class_dfs:
        for i, df in enumerate(class_dfs[label]):
            for c in df.columns:
                if c in KEEP_STRING:
                    continue
                if df[c].dtype != pl.Float64:
                    class_dfs[label][i] = class_dfs[label][i].with_columns(
                        pl.col(c).cast(pl.Float64, strict=False)
                    )

    # Concat per class
    class_frames = {}
    for label in sorted(class_dfs):
        if class_dfs[label]:
            class_frames[label] = pl.concat(class_dfs[label], how='diagonal')
            print(f'  {CLASS_NAMES[label]}: {len(class_frames[label]):,} total', flush=True)

    # Balance to min class
    target = min(len(f) for f in class_frames.values())
    print(f'\nBalancing to {target:,} per class', flush=True)

    balanced = []
    for label in sorted(class_frames):
        df = class_frames[label]
        if len(df) > target:
            df = df.sample(n=target, seed=42)
        balanced.append(df)
        print(f'  {CLASS_NAMES[label]}: {len(df):,}', flush=True)

    combined = pl.concat(balanced, how='diagonal').sample(fraction=1.0, seed=42)  # shuffle
    print(f'\nCombined: {len(combined):,} rows, {len(combined.columns)} cols', flush=True)

    # Select feature columns + meta
    keep_cols = [c for c in combined.columns if c not in SKIP]
    # Ensure actor_id appears only once
    if 'actor_id' not in keep_cols:
        combined = combined.with_columns(pl.col('src_ip').cast(pl.Utf8).alias('actor_id'))
        keep_cols.append('actor_id')
    # Always include label + label_confidence
    for c in ['label', 'label_confidence']:
        if c not in keep_cols:
            keep_cols.append(c)

    combined = combined.select(keep_cols)

    # Cast numeric columns
    for c in combined.columns:
        if c in ('actor_id',):
            continue
        if combined[c].dtype == pl.Utf8:
            combined = combined.with_columns(pl.col(c).cast(pl.Float32, strict=False).fill_null(0))

    print(f'Output: {len(combined):,} rows, {len(combined.columns)} cols', flush=True)

    # Write parquet
    combined.write_parquet(args.output)
    sz = os.path.getsize(args.output) / 1e9
    elapsed = time.time() - t0
    print(f'Saved: {args.output} ({sz:.2f} GB, {elapsed:.0f}s)', flush=True)


if __name__ == '__main__':
    main()
