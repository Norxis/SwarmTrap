#!/usr/bin/env python3
"""Prep D2 capture data for per-service CNN training.

Copied from proven prep_cnn_3class.py pattern.
Expands CNN arrays into flat columns. NO PORT/PROTO FEATURES — CNN must learn
from packet patterns only, because real-world attackers change ports.

CRITICAL: DO NOT include dst_port, ip_proto, app_proto, service_id in features.
The CNN sees ONLY packet sequences + behavioral stats. Port-independent.

Usage (run on Test):
    python3 prep_d2_cnn.py /nvme0n1-disk/ml/data/d2/d2_attack.csv \
        /nvme0n1-disk/ml/data/d2/d2_clean.csv \
        -o /nvme0n1-disk/ml/data/d2/training_d2_cnn.parquet \
        --service 1,3
"""
import argparse
import os
import time

import polars as pl

SEQ_LEN = 128

# Proven polars load params
_LOAD_PARAMS = dict(
    null_values=[r'\N', 'NULL', ''],
    infer_schema_length=50000,
    ignore_errors=True,
    truncate_ragged_lines=True,
)

# CNN array column names in ip_capture_d2
ARR_COLS = ['pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy']
ARR_PREFIXES = ['size_dir_seq', 'tcp_flags_seq', 'iat_log_ms_seq', 'iat_rtt_bin_seq', 'entropy_bin_seq']

# Static features for CNN — NO PORT, NO PROTO, NO SERVICE_ID
# CRITICAL: Port-independent. CNN learns from packet behavior only.
CNN_STATIC_COLS = [
    # Packet counts + bytes (direction-aware)
    'pkts_fwd', 'pkts_rev', 'bytes_fwd', 'bytes_rev',
    'bytes_per_pkt_fwd', 'bytes_per_pkt_rev', 'pkt_ratio', 'byte_ratio',
    # Timing
    'duration_ms', 'rtt_ms', 'pps', 'bps',
    'iat_fwd_mean_ms', 'iat_fwd_std_ms',
    'think_time_mean_ms', 'think_time_std_ms',
    'iat_to_rtt', 'payload_rtt_ratio',
    # Payload analysis
    'entropy_first', 'entropy_fwd_mean', 'entropy_rev_mean',
    'printable_frac', 'null_frac', 'byte_std', 'high_entropy_frac',
    'payload_len_first',
    # Size distribution
    'fwd_size_mean', 'fwd_size_std', 'fwd_size_min', 'fwd_size_max',
    'rev_size_mean', 'rev_size_std', 'rev_size_max',
    'hist_tiny', 'hist_small', 'hist_medium', 'hist_large', 'hist_full', 'frac_full',
    # TCP flags
    'syn_count', 'fin_count', 'rst_count', 'psh_count', 'ack_only_count',
    'conn_state', 'rst_frac', 'syn_to_data', 'psh_burst_max',
    'retransmit_est', 'window_size_init',
    # Source behavior (port-independent)
    'src_flow_count', 'src_unique_ports', 'src_unique_protos',
    'src_unique_dsts', 'src_span_min', 'src_avg_pps',
    'n_events',
]

# Columns to keep as string
_KEEP_STRING = {'src_ip', 'dst_ip', 'sensor', 'discrepancy_type', 'first_fwd_payload',
                'xgb_probs', 'first_ts', 'last_ts', 'captured_at', 'ingested_at'}

# Service IDs: 1=SSH, 3=RDP (remote access)
SERVICE_MAP = {1: 'SSH', 3: 'RDP'}


def expand_array(s: pl.Series, length: int = SEQ_LEN) -> list:
    """Expand '[1,2,3,...]' string array into flat columns using polars."""
    s = s.cast(pl.Utf8).str.strip_chars('[]"')
    cols = []
    for i in range(length):
        c = s.str.split(',').list.get(i).cast(pl.Int8, strict=False).fill_null(0)
        cols.append(c)
    return cols


def load_and_prep(path, label, services=None, n_rows=None):
    """Load CSV, filter by service, expand arrays, assign label."""
    t0 = time.time()
    kwargs = dict(_LOAD_PARAMS)
    if n_rows:
        kwargs['n_rows'] = n_rows

    df = pl.read_csv(path, **kwargs)
    print(f'  Loaded {path}: {len(df):,} rows ({time.time()-t0:.1f}s)')

    # Filter by service if specified
    if services and 'service_id' in df.columns:
        df = df.filter(pl.col('service_id').is_in(services))
        print(f'  Filtered to services {services}: {len(df):,} rows')

    # Filter: must have CNN arrays
    if 'pkt_size_dir' in df.columns:
        df = df.filter(pl.col('pkt_size_dir').is_not_null() & (pl.col('pkt_size_dir') != '[]'))
        print(f'  After CNN array filter: {len(df):,} rows')

    # Expand arrays into flat columns
    print(f'  Expanding {len(ARR_COLS)} arrays × {SEQ_LEN} tokens...', flush=True)
    t1 = time.time()
    for arr_col, prefix in zip(ARR_COLS, ARR_PREFIXES):
        if arr_col in df.columns:
            expanded = expand_array(df[arr_col], SEQ_LEN)
            for i, c in enumerate(expanded):
                df = df.with_columns(c.alias(f'{prefix}_{i+1}'))
    print(f'  Arrays expanded in {time.time()-t1:.1f}s')

    # Cast static cols to Float64
    casts = []
    for c in CNN_STATIC_COLS:
        if c in df.columns and df[c].dtype != pl.Float64:
            casts.append(pl.col(c).cast(pl.Float64, strict=False))
    if casts:
        df = df.with_columns(casts)

    # Add label
    df = df.with_columns(pl.lit(label).cast(pl.Int32).alias('label'))

    # Keep only: static features + expanded arrays + label + src_ip (for GroupKFold)
    keep_cols = ['label']
    if 'src_ip' in df.columns:
        keep_cols.append('src_ip')
    keep_cols += [c for c in CNN_STATIC_COLS if c in df.columns]
    for prefix in ARR_PREFIXES:
        keep_cols += [f'{prefix}_{i+1}' for i in range(SEQ_LEN)]
    df = df.select([c for c in keep_cols if c in df.columns])

    return df


def prep(attack_path, clean_path, output_path, services=None, n_rows=None, balance=True):
    t0 = time.time()

    print('Loading attack data (label=0)...')
    df_atk = load_and_prep(attack_path, label=0, services=services, n_rows=n_rows)

    print('Loading clean data (label=1)...')
    df_cln = load_and_prep(clean_path, label=1, services=services, n_rows=n_rows)

    # Balance
    if balance:
        n_min = min(len(df_atk), len(df_cln))
        print(f'Balancing: attack={len(df_atk):,} clean={len(df_cln):,} → {n_min:,} each')
        df_atk = df_atk.sample(n_min, seed=42)
        df_cln = df_cln.sample(n_min, seed=42)

    # Concat
    print('Concatenating...')
    df = pl.concat([df_atk, df_cln], how='diagonal')
    df = df.sample(fraction=1.0, seed=42, shuffle=True)
    print(f'Combined: {len(df):,} rows, {len(df.columns)} cols')

    # Verify NO port features leaked
    bad_cols = [c for c in df.columns if c in ('dst_port', 'ip_proto', 'app_proto', 'service_id')]
    if bad_cols:
        print(f'  WARNING: removing port features that leaked: {bad_cols}')
        df = df.drop(bad_cols)

    # Save
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    df.write_parquet(output_path)

    elapsed = time.time() - t0
    size_mb = os.path.getsize(output_path) / 1024 / 1024
    n_static = len([c for c in CNN_STATIC_COLS if c in df.columns])
    n_arr = sum(1 for p in ARR_PREFIXES if f'{p}_1' in df.columns) * SEQ_LEN
    print(f'\nSaved: {output_path} ({size_mb:.0f} MB)')
    print(f'  attack: {(df["label"] == 0).sum():,}  clean: {(df["label"] == 1).sum():,}')
    print(f'  {n_static} static features (NO PORT) + {n_arr} array tokens')
    print(f'  EXCLUDED: dst_port, ip_proto, app_proto, service_id')
    print(f'Total time: {elapsed:.1f}s')


def main():
    ap = argparse.ArgumentParser(description='Prep D2 data for per-service CNN training')
    ap.add_argument('attack', help='Attack CSV path')
    ap.add_argument('clean', help='Clean CSV path')
    ap.add_argument('-o', '--output', required=True, help='Output parquet path')
    ap.add_argument('--service', type=str, default=None,
                    help='Comma-separated service IDs to filter (e.g. 1,3 for SSH+RDP)')
    ap.add_argument('--n-rows', type=int, default=None, help='Limit rows per source (testing)')
    ap.add_argument('--no-balance', action='store_true')
    args = ap.parse_args()

    services = [int(s) for s in args.service.split(',')] if args.service else None
    prep(args.attack, args.clean, args.output,
         services=services, n_rows=args.n_rows, balance=not args.no_balance)


if __name__ == '__main__':
    main()
