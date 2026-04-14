#!/usr/bin/env python3
"""Prep 3-class CNN dataset: TCP-only, ingress-only. FAST polars + array expansion.

Loads with polars (27s proven), expands arrays into 640 flat columns, writes parquet.
Training script loads flat columns — same as XGB. No parsing at train time.

Usage:
    python3 prep_cnn_3class.py /nvme0n1-disk/ml/data -o /nvme0n1-disk/ml/data/cnn_3class.parquet
"""
import argparse
import os
import time

import polars as pl

DATA_DIR = '/nvme0n1-disk/ml/data'

CNN_STD = ['pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy']
CNN_ALT = ['size_dir_arr', 'tcp_flags_arr', 'iat_log_ms_arr', 'iat_rtt_bin_arr', 'entropy_bin_arr']
CNN_RENAME = dict(zip(CNN_ALT, CNN_STD))

KEEP_STRING = set(CNN_STD) | set(CNN_ALT) | {
    'actor_id', 'flow_id', 'session_key', 'src_ip', 'dst_ip',
    'first_ts', 'last_ts', 'ingested_at',
}

SKIP_OUTPUT = {
    'flow_id', 'session_key', 'src_ip', 'dst_ip', 'first_ts', 'last_ts',
    'ingested_at', 'capture_depth', 'vlan_id', 'src_port',
    'size_dir_arr', 'tcp_flags_arr', 'iat_log_ms_arr', 'iat_rtt_bin_arr', 'entropy_bin_arr',
}

SOURCES = [
    ('dirty_ingress_noreply.csv', 0, 'dirty noreply'),
    ('attack_flows.csv', 1, 'attack'),
    ('dirty_knock.csv', 1, 'dirty knock'),
    ('dirty_exploit.csv', 1, 'dirty exploit'),
    ('clean_real.csv', 2, 'clean real'),
]

CLASS_NAMES = {0: 'RECON', 1: 'ATTACK', 2: 'CLEAN'}

# Array expansion: raw col → flat column prefix
EXPAND_MAP = [
    ('pkt_size_dir', 'size_dir_seq'),
    ('pkt_flag', 'tcp_flags_seq'),
    ('pkt_iat_log_ms', 'iat_log_ms_seq'),
    ('pkt_iat_rtt', 'iat_rtt_bin_seq'),
    ('pkt_entropy', 'entropy_bin_seq'),
]


def load_and_normalize(filepath, label):
    """Load CSV, cast all features to Float64, filter TCP+ingress+CNN, add label."""
    t0 = time.time()
    df = pl.read_csv(filepath, null_values=[r'\N', 'NULL', ''],
                     infer_schema_length=50000, ignore_errors=True)
    n_raw = len(df)

    # Cast ALL non-string cols to Float64 (proven fix for concat mismatches)
    for c in df.columns:
        if c in KEEP_STRING:
            continue
        if df[c].dtype != pl.Float64:
            df = df.with_columns(pl.col(c).cast(pl.Float64, strict=False))

    # Rename alt CNN cols to standard
    rename = {k: v for k, v in CNN_RENAME.items() if k in df.columns}
    if rename:
        df = df.rename(rename)

    # Find CNN column
    cnn_col = None
    for c in CNN_STD:
        if c in df.columns:
            cnn_col = c
            break
    if cnn_col is None:
        print(f'  {os.path.basename(filepath)}: NO CNN, skip', flush=True)
        return None

    # Filter TCP + ingress + has CNN
    df = df.filter(
        (pl.col('ip_proto') == 6) &
        (pl.col('vlan_id') != 101) &
        pl.col(cnn_col).is_not_null() &
        (pl.col(cnn_col) != '[]') &
        (pl.col(cnn_col) != '')
    )

    # Add label
    df = df.with_columns([
        pl.lit(float(label)).alias('label'),
        pl.lit(1.0).alias('label_confidence'),
    ])

    print(f'  {os.path.basename(filepath)}: {n_raw:,} → {len(df):,} TCP+CNN → label {label} ({time.time()-t0:.0f}s)', flush=True)
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('data_dir', nargs='?', default=DATA_DIR)
    ap.add_argument('-o', '--output', default=os.path.join(DATA_DIR, 'cnn_3class_v2.parquet'))
    args = ap.parse_args()
    data = args.data_dir
    t0 = time.time()

    print('=== Loading TCP ingress + CNN ===', flush=True)
    class_dfs = {0: [], 1: [], 2: []}
    for src_file, label, desc in SOURCES:
        path = os.path.join(data, src_file)
        if not os.path.exists(path):
            print(f'  SKIP {src_file}', flush=True)
            continue
        df = load_and_normalize(path, label)
        if df is not None and len(df) > 0:
            class_dfs[label].append(df)

    # Concat per class
    class_frames = {}
    for label in sorted(class_dfs):
        if class_dfs[label]:
            class_frames[label] = pl.concat(class_dfs[label], how='diagonal')
            print(f'  {CLASS_NAMES[label]}: {len(class_frames[label]):,}', flush=True)

    target = min(len(f) for f in class_frames.values())
    print(f'\nBalancing to {target:,} per class', flush=True)

    balanced = []
    for label in sorted(class_frames):
        df = class_frames[label]
        if len(df) > target:
            df = df.sample(n=target, seed=42)
        balanced.append(df)
        print(f'  {CLASS_NAMES[label]}: {len(df):,}', flush=True)

    combined = pl.concat(balanced, how='diagonal').sample(fraction=1.0, seed=42)

    # Select output columns (drop identity, keep features + CNN arrays)
    keep = [c for c in combined.columns if c not in SKIP_OUTPUT]
    if 'actor_id' not in keep:
        keep.append('actor_id')
    combined = combined.select([c for c in keep if c in combined.columns])

    print(f'\nBefore expansion: {len(combined):,} rows, {len(combined.columns)} cols', flush=True)

    # Expand 5 CNN array columns → 640 flat columns
    for arr_col, prefix in EXPAND_MAP:
        if arr_col not in combined.columns:
            print(f'  SKIP {arr_col} (not in data)', flush=True)
            continue
        print(f'  Expanding {arr_col} → {prefix}_1..128...', flush=True)
        t1 = time.time()
        stripped = combined[arr_col].cast(pl.Utf8).str.strip_chars('[]"')
        split_col = stripped.str.split(',')
        new_cols = []
        for i in range(128):
            col_name = f'{prefix}_{i+1}'
            new_cols.append(
                split_col.list.get(i, null_on_oob=True).cast(pl.Int8, strict=False).fill_null(0).alias(col_name)
            )
        combined = combined.with_columns(new_cols)
        combined = combined.drop(arr_col)
        print(f'    done ({time.time()-t1:.1f}s)', flush=True)

    print(f'\nAfter expansion: {len(combined):,} rows, {len(combined.columns)} cols', flush=True)
    combined.write_parquet(args.output)
    sz = os.path.getsize(args.output) / 1e9
    elapsed = time.time() - t0
    print(f'Saved: {args.output} ({sz:.2f} GB, {elapsed:.0f}s)', flush=True)


if __name__ == '__main__':
    main()
