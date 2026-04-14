#!/usr/bin/env python3
"""Prepare evil_02 training CSV: EVIL (attack+recon+dirty) vs CLEAN.

Keep ALL attack + recon rows. Random sample from dirty to balance 1:1 with clean.
Computes derived features, zero-fills fingerprint/source_stats cols.
Uses all CPU cores via pyarrow/polars for max performance.
"""
import os
import time
import pyarrow.csv as pcsv
import pyarrow as pa
import polars as pl

DATA_DIR = '/nvme0n1-disk/ml/data'

DROP_COLS = [
    'flow_id', 'session_key', 'src_ip', 'dst_ip', 'src_port', 'vlan_id',
    'first_ts', 'last_ts', 'capture_depth', 'ingested_at',
    'pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy',
    'ja3_hash', 'hassh_hash', 'http_ua_hash',
    'evidence_mask', 'evidence_detail',
    'tls_version', 'tls_cipher_count', 'tls_ext_count', 'tls_has_sni',
    'ssh_kex_count',
    'http_method', 'http_uri_len', 'http_header_count',
    'http_has_body', 'http_status',
    'dns_qtype', 'dns_qname_len',
]

ZERO_FILL_COLS = [
    'ja3_freq', 'hassh_freq', 'http_ua_freq',
    'src_flow_count', 'src_unique_ports', 'src_unique_protos',
    'src_unique_dsts', 'src_span_min', 'src_avg_pps',
]


def read_csv(name):
    path = os.path.join(DATA_DIR, name)
    t0 = time.time()
    df = pl.read_csv(path, infer_schema_length=0, try_parse_dates=False)
    # Cast all string cols to numeric where possible
    for col in df.columns:
        if df[col].dtype == pl.Utf8:
            try:
                df = df.with_columns(pl.col(col).cast(pl.Float64, strict=False))
            except Exception:
                pass
    print(f'  {name}: {len(df):,} rows ({time.time()-t0:.1f}s)')
    return df


def main():
    t_start = time.time()
    print('=== prep_evil_02: EVIL vs CLEAN balanced training data ===\n')

    attack = read_csv('attack.csv')
    recon = read_csv('recon.csv')
    dirty = read_csv('dirty.csv')
    clean = read_csv('clean.csv')

    n_clean = len(clean)
    n_attack = len(attack)
    n_recon = len(recon)
    n_fixed = n_attack + n_recon
    n_dirty_needed = n_clean - n_fixed

    print(f'\nBalance plan:')
    print(f'  Clean:  {n_clean:,}')
    print(f'  Attack: {n_attack:,} (keep all)')
    print(f'  Recon:  {n_recon:,} (keep all)')
    print(f'  Dirty:  {len(dirty):,} -> sample {n_dirty_needed:,}')

    if n_dirty_needed <= 0:
        print('ERROR: attack+recon already >= clean, no dirty needed')
        return
    if n_dirty_needed > len(dirty):
        print(f'WARNING: need {n_dirty_needed:,} dirty but only have {len(dirty):,}, using all')
        n_evil_total = n_fixed + len(dirty)
        print(f'  Downsampling clean from {n_clean:,} to {n_evil_total:,}')
        clean = clean.sample(n=n_evil_total, seed=42)
        n_dirty_needed = len(dirty)

    # Labels
    attack = attack.with_columns(pl.lit(1).alias('label'), pl.lit(5.0).alias('label_confidence'))
    recon = recon.with_columns(pl.lit(1).alias('label'), pl.lit(2.0).alias('label_confidence'))
    clean = clean.with_columns(pl.lit(5).alias('label'), pl.lit(1.0).alias('label_confidence'))

    dirty_sampled = dirty.sample(n=n_dirty_needed, seed=42)
    dirty_sampled = dirty_sampled.with_columns(pl.lit(1).alias('label'), pl.lit(2.0).alias('label_confidence'))
    del dirty

    # Align columns before concat — use clean's columns as base, add missing as null
    all_frames = [attack, recon, dirty_sampled, clean]
    all_cols = set()
    for f in all_frames:
        all_cols.update(f.columns)

    aligned = []
    for f in all_frames:
        for col in all_cols - set(f.columns):
            f = f.with_columns(pl.lit(None).alias(col))
        aligned.append(f)

    print('\nConcatenating ...')
    df = pl.concat(aligned, how='diagonal_relaxed')
    del attack, recon, dirty_sampled, clean, aligned

    n_evil = int((df['label'] == 1).sum())
    n_clean_final = int((df['label'] == 5).sum())
    print(f'Combined: {len(df):,} rows (EVIL={n_evil:,}, CLEAN={n_clean_final:,}, ratio=1:{n_clean_final/n_evil:.2f})')

    # Drop unwanted columns
    drop_existing = [c for c in DROP_COLS if c in df.columns]
    df = df.drop(drop_existing)

    # Derived features
    df = df.with_columns([
        pl.when(pl.col('pkts_fwd') > 0).then(pl.col('bytes_fwd') / pl.col('pkts_fwd')).otherwise(0).alias('bytes_per_pkt_fwd'),
        pl.when(pl.col('pkts_rev') > 0).then(pl.col('bytes_rev') / pl.col('pkts_rev')).otherwise(0).alias('bytes_per_pkt_rev'),
        pl.when((pl.col('pkts_fwd') + pl.col('pkts_rev')) > 0)
            .then(pl.col('pkts_fwd') / (pl.col('pkts_fwd') + pl.col('pkts_rev')))
            .otherwise(0).alias('pkt_ratio'),
        pl.when((pl.col('bytes_fwd') + pl.col('bytes_rev')) > 0)
            .then(pl.col('bytes_fwd') / (pl.col('bytes_fwd') + pl.col('bytes_rev')))
            .otherwise(0).alias('byte_ratio'),
    ])

    # Zero-fill cols
    for col in ZERO_FILL_COLS:
        if col not in df.columns:
            df = df.with_columns(pl.lit(0).alias(col))

    # Shuffle
    df = df.sample(fraction=1.0, seed=42, shuffle=True)

    feat_cols = [c for c in df.columns if c not in ['actor_id', 'label', 'label_confidence']]
    print(f'\nFeatures: {len(feat_cols)}')
    print(f'Feature names: {feat_cols}')

    out_path = os.path.join(DATA_DIR, 'evil_02_training.csv')
    print(f'\nWriting {out_path} ...')
    df.write_csv(out_path)
    size_mb = os.path.getsize(out_path) / 1e6
    print(f'Done: {len(df):,} rows, {size_mb:.0f} MB ({time.time()-t_start:.1f}s total)')
    print(f'\nTrain command:')
    print(f'  python3 -u /sdb-disk/ml/train_xgb.py {out_path} --folds 5 --gpu --evil --scale-pos-weight 1.0')


if __name__ == '__main__':
    main()
