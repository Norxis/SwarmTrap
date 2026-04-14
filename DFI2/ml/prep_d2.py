#!/usr/bin/env python3
"""Prep D2 capture data for XGB training.

Copied from proven prep_cnn_3class.py pattern.
Merges attack + clean CSVs, assigns binary labels, balances, outputs parquet.

Usage (run on Test):
    python3 prep_d2.py /nvme0n1-disk/ml/data/d2/d2_attack.csv /nvme0n1-disk/ml/data/d2/d2_clean.csv \
        -o /nvme0n1-disk/ml/data/d2/training_d2.parquet
"""
import argparse
import os
import time

import polars as pl

# Proven polars load params
_LOAD_PARAMS = dict(
    null_values=[r'\N', 'NULL', ''],
    infer_schema_length=50000,
    ignore_errors=True,
    truncate_ragged_lines=True,
)

# Columns to DROP from training data (identity, meta, strings, old model output, zero-fill)
_DROP_COLS = {
    # Identity / meta — not features
    'src_ip', 'dst_ip', 'sensor', 'captured_at', 'first_ts', 'last_ts', 'ingested_at',
    'discrepancy_type', 'truth_label', 'service_id', 'service_class',
    'capture_value_score', 'label_confidence', 'evidence_mask',
    # Port/proto — attackers change ports, model must learn behavior not ports
    'dst_port', 'ip_proto', 'app_proto',
    # Old model output — retraining, don't use old model as feature
    'xgb_class', 'xgb_confidence', 'xgb_probs',
    # CNN arrays as strings — XGB can't use these
    'pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy',
    'first_fwd_payload',
    # F7 fingerprints — ALL ZEROS (GOD 1 has no DPI)
    'ja3_freq', 'tls_version', 'tls_cipher_count', 'tls_ext_count', 'tls_has_sni',
    'hassh_freq', 'ssh_kex_count',
    'http_method', 'http_uri_len', 'http_header_count', 'http_ua_freq', 'http_has_body', 'http_status',
    'dns_qtype', 'dns_qname_len',
}


def load_and_label(path, label, n_rows=None):
    """Load CSV, drop junk, assign label, cast types."""
    t0 = time.time()
    kwargs = dict(_LOAD_PARAMS)
    if n_rows:
        kwargs['n_rows'] = n_rows

    df = pl.read_csv(path, **kwargs)
    raw_cols = len(df.columns)
    print(f'  Loaded {path}: {len(df):,} rows, {raw_cols} cols ({time.time()-t0:.1f}s)')

    # Drop junk columns
    drop = [c for c in df.columns if c in _DROP_COLS]
    if drop:
        df = df.drop(drop)
        print(f'  Dropped {len(drop)} cols: {drop[:5]}{"..." if len(drop) > 5 else ""}')

    # Cast ALL remaining cols to Float64 before concat (proven pattern)
    casts = []
    for c in df.columns:
        if df[c].dtype != pl.Float64:
            casts.append(pl.col(c).cast(pl.Float64, strict=False))
    if casts:
        df = df.with_columns(casts)

    # Add label
    df = df.with_columns(pl.lit(label).cast(pl.Int32).alias('label'))
    return df


def prep(attack_path, clean_path, output_path, n_rows=None, balance=True):
    t0 = time.time()

    print('Loading attack data (label=0)...')
    df_atk = load_and_label(attack_path, label=0, n_rows=n_rows)

    print('Loading clean data (label=1)...')
    df_cln = load_and_label(clean_path, label=1, n_rows=n_rows)

    # Balance — downsample majority class
    if balance:
        n_min = min(len(df_atk), len(df_cln))
        print(f'Balancing: attack={len(df_atk):,} clean={len(df_cln):,} → {n_min:,} each')
        df_atk = df_atk.sample(n_min, seed=42)
        df_cln = df_cln.sample(n_min, seed=42)

    # Concat (diagonal handles mismatched columns)
    print('Concatenating...')
    df = pl.concat([df_atk, df_cln], how='diagonal')
    print(f'Combined: {len(df):,} rows, {len(df.columns)} cols')

    # Shuffle
    df = df.sample(fraction=1.0, seed=42, shuffle=True)

    # Save
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    df.write_parquet(output_path)

    elapsed = time.time() - t0
    size_mb = os.path.getsize(output_path) / 1024 / 1024

    # Report
    print(f'\n{"="*60}')
    print(f'DATASET REPORT')
    print(f'{"="*60}')
    print(f'Output: {output_path} ({size_mb:.0f} MB)')
    print(f'Rows: {len(df):,}  Cols: {len(df.columns)}')
    print(f'  ATTACK(0): {(df["label"] == 0).sum():,}')
    print(f'  CLEAN(1):  {(df["label"] == 1).sum():,}')
    print(f'\nFeature columns ({len(df.columns) - 1}):')
    for c in sorted(df.columns):
        if c == 'label':
            continue
        nulls = df[c].null_count()
        dtype = str(df[c].dtype)
        print(f'  {c:35s} {dtype:10s} nulls={nulls}')
    print(f'\nDropped from source: {sorted(_DROP_COLS)}')
    print(f'Time: {elapsed:.1f}s')
    print(f'{"="*60}')


def main():
    ap = argparse.ArgumentParser(description='Prep D2 data for XGB training')
    ap.add_argument('attack', help='Attack CSV path')
    ap.add_argument('clean', help='Clean CSV path')
    ap.add_argument('-o', '--output', required=True, help='Output parquet path')
    ap.add_argument('--n-rows', type=int, default=None, help='Limit rows per source (for testing)')
    ap.add_argument('--no-balance', action='store_true', help='Skip balancing')
    args = ap.parse_args()
    prep(args.attack, args.clean, args.output, n_rows=args.n_rows, balance=not args.no_balance)


if __name__ == '__main__':
    main()
