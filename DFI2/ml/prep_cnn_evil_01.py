#!/usr/bin/env python3
# Updated for combined 722-col dataset (XGB+CNN in one row)
"""Prepare CNN evil_01 training data.

Reads 4 data sources with polars (max CPU), expands pkt_* array columns to
128-position sequences (or uses pre-expanded sequences from combined parquet),
balances 1:1, computes derived features, writes parquet.
Weights: attack=5, recon/dirty=2, clean=1.
src_* columns are REAL values — no zero-fill.
"""
import os
import time

import numpy as np
import polars as pl

SEQ_LEN = 128
DATA_DIR = '/nvme0n1-disk/ml/data'

CHANNELS = [
    ('pkt_size_dir', 'size_dir_seq'),
    ('pkt_flag', 'tcp_flags_seq'),
    ('pkt_iat_log_ms', 'iat_log_ms_seq'),
    ('pkt_iat_rtt', 'iat_rtt_bin_seq'),
    ('pkt_entropy', 'entropy_bin_seq'),
]

DROP_COLS = [
    'flow_id', 'session_key', 'src_ip', 'dst_ip', 'src_port', 'vlan_id',
    'first_ts', 'last_ts', 'capture_depth', 'ingested_at',
    'ja3_hash', 'hassh_hash', 'http_ua_hash',
    'evidence_mask', 'evidence_detail',
]

# Only keep these columns from source data (avoids type conflicts on unused cols)
# src_* and fingerprint cols now included — real values in combined format.
KEEP_COLS = [
    'actor_id',
    'dst_port', 'ip_proto', 'app_proto', 'pkts_fwd', 'pkts_rev', 'bytes_fwd', 'bytes_rev',
    'rtt_ms', 'duration_ms', 'iat_fwd_mean_ms', 'iat_fwd_std_ms',
    'think_time_mean_ms', 'think_time_std_ms', 'iat_to_rtt', 'pps', 'bps',
    'payload_rtt_ratio', 'n_events',
    'fwd_size_mean', 'fwd_size_std', 'fwd_size_min', 'fwd_size_max',
    'rev_size_mean', 'rev_size_std', 'rev_size_max',
    'hist_tiny', 'hist_small', 'hist_medium', 'hist_large', 'hist_full', 'frac_full',
    'syn_count', 'fin_count', 'rst_count', 'psh_count', 'ack_only_count',
    'conn_state', 'rst_frac', 'syn_to_data', 'psh_burst_max', 'retransmit_est',
    'window_size_init', 'entropy_first', 'entropy_fwd_mean', 'entropy_rev_mean',
    'printable_frac', 'null_frac', 'byte_std', 'high_entropy_frac', 'payload_len_first',
    # Fingerprint + source stats — real values in combined format (not zero-filled)
    'ja3_freq', 'tls_version', 'tls_cipher_count', 'tls_ext_count', 'tls_has_sni',
    'hassh_freq', 'ssh_kex_count',
    'http_method', 'http_uri_len', 'http_header_count', 'http_ua_freq',
    'http_has_body', 'http_status',
    'dns_qtype', 'dns_qname_len',
    'src_flow_count', 'src_unique_ports', 'src_unique_protos',
    'src_unique_dsts', 'src_span_min', 'src_avg_pps',
    # pkt arrays (legacy CSV only — combined parquet already has expanded sequence cols)
    'pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy',
    'label', 'label_confidence',
]


def expand_channel(df, csv_col, prefix):
    """Expand a pkt_* array string column into 128 individual Int16 columns."""
    t0 = time.time()
    print(f'  {csv_col} -> {prefix}_1..{prefix}_{SEQ_LEN} ...', flush=True)

    # Parse "[1,2,3]" -> List[Utf8], then get each element
    parsed_col = f'_parsed_{csv_col}'
    df = df.with_columns(
        pl.col(csv_col).str.strip_chars('[]').str.split(',').alias(parsed_col)
    )

    exprs = []
    for i in range(SEQ_LEN):
        exprs.append(
            pl.col(parsed_col).list.get(i, null_on_oob=True)
            .cast(pl.Int16, strict=False)
            .fill_null(0)
            .alias(f'{prefix}_{i+1}')
        )
    df = df.with_columns(exprs).drop([csv_col, parsed_col])
    print(f'    Done in {time.time() - t0:.1f}s', flush=True)
    return df


def read_data(name):
    """Read combined parquet or legacy CSV. Returns polars DataFrame."""
    path = os.path.join(DATA_DIR, name)
    t0 = time.time()
    pkt_set = {'pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy',
               'actor_id', 'label', 'label_confidence'}
    if name.endswith('.parquet'):
        df = pl.read_parquet(path)
    else:
        df = pl.read_csv(path, infer_schema_length=10000, null_values=[r'\N', ''], try_parse_dates=False)
        casts = [
            pl.col(c).cast(pl.Float64, strict=False)
            for c in df.columns
            if c not in pkt_set and df[c].dtype == pl.Utf8
        ]
        if casts:
            df = df.with_columns(casts)
    avail = [c for c in KEEP_COLS if c in df.columns]
    df = df.select(avail)
    print(f'  {name}: {len(df):,} rows, {len(df.columns)} cols ({time.time()-t0:.1f}s)', flush=True)
    return df


def main():
    t_start = time.time()
    print('=== prep_cnn_evil_01: EVIL vs CLEAN CNN training data ===\n', flush=True)
    print('Source: combined 722-col parquet (real src_* values, no zero-fill)\n', flush=True)

    # Accept combined parquet files if present, fall back to legacy CSVs
    def _src(base):
        parquet = f'{base.replace(".csv", "")}.parquet'
        return parquet if os.path.exists(os.path.join(DATA_DIR, parquet)) else base

    # Read all 4 data sources with polars (multi-threaded, max CPU)
    print('Reading data with polars (all cores)...', flush=True)
    t0 = time.time()
    attack = read_data(_src('attack.csv'))
    recon = read_data(_src('recon.csv'))
    dirty = read_data(_src('dirty.csv'))
    clean = read_data(_src('clean.csv'))
    print(f'  Read all in {time.time() - t0:.1f}s', flush=True)

    # Set labels and weights: attack=5, recon/dirty=2, clean=1
    attack = attack.with_columns(pl.lit(1).alias('label'), pl.lit(5.0).alias('label_confidence'))
    recon = recon.with_columns(pl.lit(1).alias('label'), pl.lit(2.0).alias('label_confidence'))
    dirty = dirty.with_columns(pl.lit(1).alias('label'), pl.lit(2.0).alias('label_confidence'))
    clean = clean.with_columns(pl.lit(5).alias('label'), pl.lit(1.0).alias('label_confidence'))

    # read_data() already selects KEEP_COLS — no additional selection needed.
    # Ensure pkt_* are String type for all DataFrames (legacy CSV only)
    pkt_cols = ['pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy']
    for df_ref in [attack, recon, dirty, clean]:
        for col in pkt_cols:
            if col in df_ref.columns and df_ref[col].dtype != pl.Utf8:
                df_ref = df_ref.with_columns(pl.col(col).cast(pl.Utf8))

    # Concat evil sources
    print('\nConcatenating evil sources...', flush=True)
    evil = pl.concat([attack, recon, dirty], how='vertical_relaxed')
    del attack, recon, dirty
    print(f'  Evil total: {len(evil):,}', flush=True)

    # Balance 1:1
    n_clean = len(clean)
    print(f'  Downsampling evil from {len(evil):,} to {n_clean:,}...', flush=True)
    evil = evil.sample(n=n_clean, seed=42)

    df = pl.concat([evil, clean], how='vertical_relaxed')
    del evil, clean
    print(f'  Combined: {len(df):,} rows', flush=True)

    # Coerce all numeric columns: replace \N with null, cast to Float64
    print('\nCoercing numeric columns (handling \\N nulls)...', flush=True)
    pkt_cols_set = {'pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy'}
    skip_cols = pkt_cols_set | {'actor_id', 'label', 'label_confidence'}
    numeric_casts = []
    for col in df.columns:
        if col in skip_cols:
            continue
        if df[col].dtype == pl.Utf8:
            numeric_casts.append(
                pl.col(col).str.replace(r'\\N', '').cast(pl.Float64, strict=False).fill_null(0.0).alias(col)
            )
    if numeric_casts:
        df = df.with_columns(numeric_casts)

    # Derived features (only computed if not already present from combined parquet)
    print('Computing derived features (if not already present)...', flush=True)
    derived = []
    if 'bytes_per_pkt_fwd' not in df.columns:
        derived.append(
            (pl.when(pl.col('pkts_fwd') > 0)
             .then(pl.col('bytes_fwd') / pl.col('pkts_fwd'))
             .otherwise(0.0)).cast(pl.Float32).alias('bytes_per_pkt_fwd'))
    if 'bytes_per_pkt_rev' not in df.columns:
        derived.append(
            (pl.when(pl.col('pkts_rev') > 0)
             .then(pl.col('bytes_rev') / pl.col('pkts_rev'))
             .otherwise(0.0)).cast(pl.Float32).alias('bytes_per_pkt_rev'))
    if 'pkt_ratio' not in df.columns:
        derived.append(
            (pl.when((pl.col('pkts_fwd') + pl.col('pkts_rev')) > 0)
             .then(pl.col('pkts_fwd') / (pl.col('pkts_fwd') + pl.col('pkts_rev')))
             .otherwise(0.0)).cast(pl.Float32).alias('pkt_ratio'))
    if 'byte_ratio' not in df.columns:
        derived.append(
            (pl.when((pl.col('bytes_fwd') + pl.col('bytes_rev')) > 0)
             .then(pl.col('bytes_fwd') / (pl.col('bytes_fwd') + pl.col('bytes_rev')))
             .otherwise(0.0)).cast(pl.Float32).alias('byte_ratio'))
    if derived:
        df = df.with_columns(derived)

    # No zero-fill: src_* and fingerprint cols are REAL values from combined dataset.
    # For legacy CSV sources that lack these columns, fill with 0 only if missing.
    OPTIONAL_COLS = [
        'ja3_freq', 'tls_version', 'tls_cipher_count', 'tls_ext_count', 'tls_has_sni',
        'hassh_freq', 'ssh_kex_count',
        'http_method', 'http_uri_len', 'http_header_count', 'http_ua_freq',
        'http_has_body', 'http_status',
        'dns_qtype', 'dns_qname_len',
        'src_flow_count', 'src_unique_ports', 'src_unique_protos',
        'src_unique_dsts', 'src_span_min', 'src_avg_pps',
    ]
    missing_fill = [
        pl.lit(0).cast(pl.Float32).alias(col)
        for col in OPTIONAL_COLS if col not in df.columns
    ]
    if missing_fill:
        print(f'  Filling {len(missing_fill)} missing optional cols with 0 (legacy CSV source)', flush=True)
        df = df.with_columns(missing_fill)

    # Check if sequences are already expanded (combined parquet) or need expansion (legacy CSV)
    seq_already_expanded = 'size_dir_seq_1' in df.columns

    # Expand pkt_* array columns to 128 sequence columns each (legacy CSV only)
    if seq_already_expanded:
        print('\nSequences already expanded (combined parquet format) — skipping expansion.', flush=True)
    else:
        print('\nExpanding packet sequences (5 channels x 128 positions)...', flush=True)
        t_expand = time.time()
        for csv_col, prefix in CHANNELS:
            if csv_col in df.columns:
                df = expand_channel(df, csv_col, prefix)
            else:
                print(f'  WARNING: {csv_col} missing — filling zeros', flush=True)
                df = df.with_columns([
                    pl.lit(0).cast(pl.Int16).alias(f'{prefix}_{i+1}')
                    for i in range(SEQ_LEN)
                ])
        print(f'  All channels expanded in {time.time() - t_expand:.1f}s', flush=True)

    # Shuffle
    print('\nShuffling...', flush=True)
    df = df.sample(fraction=1.0, seed=42, shuffle=True)

    # Stats
    n_evil = int((df['label'] == 1).sum())
    n_clean_final = int((df['label'] == 5).sum())
    seq_cols = [c for c in df.columns
                if any(c.startswith(p + '_') for _, p in CHANNELS)]
    meta_cols = ['actor_id', 'label', 'label_confidence']
    static_cols = [c for c in df.columns if c not in seq_cols + meta_cols]

    print(f'\nLabel distribution: EVIL={n_evil:,}  CLEAN={n_clean_final:,}', flush=True)
    print(f'Sequence columns: {len(seq_cols)} (5 x {SEQ_LEN})', flush=True)
    print(f'Static feature columns: {len(static_cols)}', flush=True)
    print(f'Total columns: {len(df.columns)}', flush=True)

    # Write parquet (much faster than CSV for 685 columns)
    out_path = os.path.join(DATA_DIR, 'cnn_evil_01_training.parquet')
    print(f'\nWriting {out_path} ...', flush=True)
    t_write = time.time()
    df.write_parquet(out_path, compression='zstd')
    size_mb = os.path.getsize(out_path) / 1e6
    print(f'  Written in {time.time() - t_write:.1f}s, {size_mb:.0f} MB', flush=True)

    elapsed = time.time() - t_start
    print(f'\nTotal prep time: {elapsed:.0f}s', flush=True)
    print(f'\nTrain command:', flush=True)
    print(f'  python3 -u /nvme0n1-disk/ml/train_cnn.py {out_path} '
          f'--epochs 50 --batch-size 16384 --lr 0.004 --folds 5 --evil '
          f'-o /nvme0n1-disk/ml/models', flush=True)


if __name__ == '__main__':
    main()
