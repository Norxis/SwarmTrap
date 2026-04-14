#!/usr/bin/env python3
# Updated for combined 722-col dataset (XGB+CNN in one row)
"""Prepare CNN evil_02 training parquet.

Balance: ALL attack + ALL recon + random dirty sample to fill gap = ALL clean (1:1).
Reads combined 722-col parquet (exported via export.py combined format) OR falls back to
expanding pkt_* array strings from legacy CSV -> 128-position sequence columns (5 channels).
src_* columns are REAL values — no zero-fill.
Uses polars (multi-threaded, max CPU). Writes zstd parquet.
"""
import os
import time

import polars as pl

DATA_DIR = '/nvme0n1-disk/ml/data'
SEQ_LEN = 128

CHANNELS = [
    ('pkt_size_dir',   'size_dir_seq'),
    ('pkt_flag',       'tcp_flags_seq'),
    ('pkt_iat_log_ms', 'iat_log_ms_seq'),
    ('pkt_iat_rtt',    'iat_rtt_bin_seq'),
    ('pkt_entropy',    'entropy_bin_seq'),
]

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

PKT_SET = {'pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy',
           'actor_id', 'label', 'label_confidence'}


def read_data(name):
    """Read combined parquet or legacy CSV. Returns polars DataFrame."""
    path = os.path.join(DATA_DIR, name)
    t0 = time.time()
    if name.endswith('.parquet'):
        df = pl.read_parquet(path)
    else:
        df = pl.read_csv(path, infer_schema_length=0, null_values=[r'\N', ''], try_parse_dates=False)
        # Cast string cols to float except pkt/meta cols
        casts = [
            pl.col(c).cast(pl.Float64, strict=False)
            for c in df.columns
            if c not in PKT_SET and df[c].dtype == pl.Utf8
        ]
        if casts:
            df = df.with_columns(casts)
    # Select only needed cols
    avail = [c for c in KEEP_COLS if c in df.columns]
    df = df.select(avail)
    print(f'  {name}: {len(df):,} rows, {len(df.columns)} cols ({time.time()-t0:.1f}s)', flush=True)
    return df


# Keep legacy alias for backwards compatibility
def read_csv(name):
    return read_data(name)


def expand_channel(df, csv_col, prefix):
    t0 = time.time()
    print(f'  {csv_col} -> {prefix}_1..{SEQ_LEN} ...', flush=True)
    parsed = f'_p_{csv_col}'
    df = df.with_columns(
        pl.col(csv_col).str.strip_chars('[]').str.split(',').alias(parsed)
    )
    exprs = [
        pl.col(parsed).list.get(i, null_on_oob=True)
          .cast(pl.Int16, strict=False)
          .fill_null(0)
          .alias(f'{prefix}_{i+1}')
        for i in range(SEQ_LEN)
    ]
    df = df.with_columns(exprs).drop([csv_col, parsed])
    print(f'    done {time.time()-t0:.1f}s', flush=True)
    return df


def main():
    t_start = time.time()
    print('=== prep_cnn_evil_02: CNN EVIL vs CLEAN ===\n', flush=True)
    print('Source: combined 722-col parquet (real src_* values, no zero-fill)\n', flush=True)

    # Accept combined parquet files if present, fall back to legacy CSVs
    def _src(base):
        parquet = f'{base.replace(".csv", "")}.parquet'
        return parquet if os.path.exists(os.path.join(DATA_DIR, parquet)) else base

    # Read
    print('Reading data (all cores)...', flush=True)
    attack = read_data(_src('attack.csv'))
    recon  = read_data(_src('recon.csv'))
    dirty  = read_data(_src('dirty.csv'))
    clean  = read_data(_src('clean.csv'))

    n_clean        = len(clean)
    n_attack       = len(attack)
    n_recon        = len(recon)
    n_fixed        = n_attack + n_recon
    n_dirty_needed = n_clean - n_fixed

    print(f'\nBalance plan:', flush=True)
    print(f'  Clean:  {n_clean:,}  (keep all)', flush=True)
    print(f'  Attack: {n_attack:,} (keep all)', flush=True)
    print(f'  Recon:  {n_recon:,} (keep all)', flush=True)
    print(f'  Dirty:  {len(dirty):,} -> sample {max(0,n_dirty_needed):,}', flush=True)

    if n_dirty_needed < 0:
        # attack+recon already exceed clean — downsample clean to match
        print(f'WARNING: attack+recon ({n_fixed:,}) > clean ({n_clean:,}), downsampling clean', flush=True)
        clean = clean.sample(n=n_fixed, seed=42)
        n_dirty_needed = 0

    # Assign labels
    attack = attack.with_columns(pl.lit(1).alias('label'), pl.lit(5.0).alias('label_confidence'))
    recon  = recon.with_columns( pl.lit(1).alias('label'), pl.lit(2.0).alias('label_confidence'))
    clean  = clean.with_columns( pl.lit(5).alias('label'), pl.lit(1.0).alias('label_confidence'))

    if n_dirty_needed > 0:
        dirty_sampled = dirty.sample(n=n_dirty_needed, seed=42)
    else:
        dirty_sampled = dirty.clear()
    dirty_sampled = dirty_sampled.with_columns(
        pl.lit(1).alias('label'), pl.lit(2.0).alias('label_confidence')
    )
    del dirty

    # Concat (diagonal_relaxed handles column mismatches between dirty 66-col and others 84-col)
    print('\nConcatenating...', flush=True)
    df = pl.concat([attack, recon, dirty_sampled, clean], how='diagonal_relaxed')
    del attack, recon, dirty_sampled, clean

    n_evil    = int((df['label'] == 1).sum())
    n_clean_f = int((df['label'] == 5).sum())
    print(f'  Combined: {len(df):,} rows  EVIL={n_evil:,}  CLEAN={n_clean_f:,}', flush=True)

    # Coerce any remaining string cols (nulls from diagonal_relaxed)
    print('\nCoercing numeric columns...', flush=True)
    casts = [
        pl.col(c).cast(pl.Float64, strict=False).fill_null(0.0).alias(c)
        for c in df.columns
        if c not in PKT_SET and df[c].dtype == pl.Utf8
    ]
    if casts:
        df = df.with_columns(casts)
    # Fill remaining nulls in numeric cols
    num_cols = [c for c in df.columns if c not in PKT_SET and df[c].dtype in (pl.Float64, pl.Float32)]
    df = df.with_columns([pl.col(c).fill_null(0.0) for c in num_cols])

    # Derived features (only computed if not already present from combined parquet)
    print('Computing derived features (if not already present)...', flush=True)
    derived = []
    if 'bytes_per_pkt_fwd' not in df.columns:
        derived.append(
            pl.when(pl.col('pkts_fwd') > 0)
              .then(pl.col('bytes_fwd') / pl.col('pkts_fwd'))
              .otherwise(0.0).cast(pl.Float32).alias('bytes_per_pkt_fwd'))
    if 'bytes_per_pkt_rev' not in df.columns:
        derived.append(
            pl.when(pl.col('pkts_rev') > 0)
              .then(pl.col('bytes_rev') / pl.col('pkts_rev'))
              .otherwise(0.0).cast(pl.Float32).alias('bytes_per_pkt_rev'))
    if 'pkt_ratio' not in df.columns:
        derived.append(
            pl.when((pl.col('pkts_fwd') + pl.col('pkts_rev')) > 0)
              .then(pl.col('pkts_fwd') / (pl.col('pkts_fwd') + pl.col('pkts_rev')))
              .otherwise(0.0).cast(pl.Float32).alias('pkt_ratio'))
    if 'byte_ratio' not in df.columns:
        derived.append(
            pl.when((pl.col('bytes_fwd') + pl.col('bytes_rev')) > 0)
              .then(pl.col('bytes_fwd') / (pl.col('bytes_fwd') + pl.col('bytes_rev')))
              .otherwise(0.0).cast(pl.Float32).alias('byte_ratio'))
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

    # Expand pkt_* → 128 sequence columns per channel (legacy CSV only)
    if seq_already_expanded:
        print('\nSequences already expanded (combined parquet format) — skipping expansion.', flush=True)
    else:
        print('\nExpanding packet sequences (5 channels x 128)...', flush=True)
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
        print(f'  All channels expanded in {time.time()-t_expand:.1f}s', flush=True)

    # Shuffle
    print('\nShuffling...', flush=True)
    df = df.sample(fraction=1.0, seed=42, shuffle=True)

    # Report layout
    seq_cols    = [c for c in df.columns if any(c.startswith(p + '_') for _, p in CHANNELS)]
    meta_cols   = ['actor_id', 'label', 'label_confidence']
    static_cols = [c for c in df.columns if c not in seq_cols + meta_cols]
    print(f'\nLayout: {len(seq_cols)} seq + {len(static_cols)} static + {len(meta_cols)} meta = {len(df.columns)} cols', flush=True)
    print(f'Static cols ({len(static_cols)}): {static_cols}', flush=True)

    # Write parquet
    out_path = os.path.join(DATA_DIR, 'cnn_evil_02_training.parquet')
    print(f'\nWriting {out_path} ...', flush=True)
    t_write = time.time()
    df.write_parquet(out_path, compression='zstd')
    size_mb = os.path.getsize(out_path) / 1e6
    print(f'Written: {len(df):,} rows, {size_mb:.0f} MB ({time.time()-t_write:.1f}s)', flush=True)
    print(f'Total time: {time.time()-t_start:.0f}s', flush=True)

    print(f'\nTrain cmd:', flush=True)
    print(f'  python3 -u /nvme0n1-disk/ml/train_cnn.py {out_path} '
          f'--epochs 50 --batch-size 16384 --lr 0.004 --folds 5 --evil '
          f'-o /nvme0n1-disk/ml/models', flush=True)


if __name__ == '__main__':
    main()
