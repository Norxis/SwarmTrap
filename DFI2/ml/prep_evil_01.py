#!/usr/bin/env python3
"""Prepare evil_01 training CSV: EVIL (attack+recon+dirty) vs CLEAN.

Combines 4 CSVs, balances 1:1, computes derived features, zero-fills 21
fingerprint/source_stats to match v7 inline scoring profile. Output: 75 features.
"""
import os
import numpy as np
import pandas as pd

DATA_DIR = '/nvme0n1-disk/ml/data'

DROP_COLS = [
    'flow_id', 'session_key', 'src_ip', 'dst_ip', 'src_port', 'vlan_id',
    'first_ts', 'last_ts', 'capture_depth', 'ingested_at',
    # CNN packet arrays
    'pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy',
    # Raw hashes (replaced by zero-filled freq cols)
    'ja3_hash', 'hassh_hash', 'http_ua_hash',
    # Evidence (not a scoring feature)
    'evidence_mask', 'evidence_detail',
]

FINGERPRINT_COLS = [
    'ja3_freq', 'tls_version', 'tls_cipher_count', 'tls_ext_count', 'tls_has_sni',
    'hassh_freq', 'ssh_kex_count',
    'http_method', 'http_uri_len', 'http_header_count', 'http_ua_freq',
    'http_has_body', 'http_status',
    'dns_qtype', 'dns_qname_len',
]
SOURCE_STATS_COLS = [
    'src_flow_count', 'src_unique_ports', 'src_unique_protos',
    'src_unique_dsts', 'src_span_min', 'src_avg_pps',
]


def main():
    print('=== prep_evil_01: EVIL vs CLEAN balanced training data ===\n')

    # Read all 4 CSVs
    print('Reading attack.csv ...')
    attack = pd.read_csv(os.path.join(DATA_DIR, 'attack.csv'), engine='pyarrow')
    print(f'  {len(attack):,} rows')

    print('Reading recon.csv ...')
    recon = pd.read_csv(os.path.join(DATA_DIR, 'recon.csv'), engine='pyarrow')
    print(f'  {len(recon):,} rows')

    print('Reading dirty.csv ...')
    dirty = pd.read_csv(os.path.join(DATA_DIR, 'dirty.csv'), engine='pyarrow')
    print(f'  {len(dirty):,} rows')

    print('Reading clean.csv ...')
    clean = pd.read_csv(os.path.join(DATA_DIR, 'clean.csv'), engine='pyarrow')
    print(f'  {len(clean):,} rows')

    # Set labels: evil=1, clean=5 (train_xgb.py maps 5→0, else→1)
    # Weights: attack=5 (evidence-confirmed), recon/dirty=2 (honeypot, 100% bad), clean=1
    attack['label'] = 1
    attack['label_confidence'] = 5.0
    recon['label'] = 1
    recon['label_confidence'] = 2.0
    dirty['label'] = 1
    dirty['label_confidence'] = 2.0
    clean['label'] = 5
    clean['label_confidence'] = 1.0

    # Concat evil sources
    print('\nConcatenating evil sources ...')
    evil = pd.concat([attack, recon, dirty], ignore_index=True)
    del attack, recon, dirty
    print(f'  Evil total: {len(evil):,} rows')

    # Balance 1:1: downsample evil to match clean
    n_clean = len(clean)
    print(f'  Clean: {n_clean:,} rows')
    print(f'  Downsampling evil from {len(evil):,} to {n_clean:,} ...')
    evil = evil.sample(n=n_clean, random_state=42)

    # Concat balanced
    df = pd.concat([evil, clean], ignore_index=True)
    del evil, clean
    print(f'Combined (balanced): {len(df):,} rows')

    # Drop unwanted columns
    df.drop(columns=[c for c in DROP_COLS if c in df.columns], inplace=True)

    # Compute 4 derived features (matching v_xgb view)
    df['bytes_per_pkt_fwd'] = np.where(df['pkts_fwd'] > 0, df['bytes_fwd'] / df['pkts_fwd'], 0)
    df['bytes_per_pkt_rev'] = np.where(df['pkts_rev'] > 0, df['bytes_rev'] / df['pkts_rev'], 0)
    total_pkts = df['pkts_fwd'] + df['pkts_rev']
    df['pkt_ratio'] = np.where(total_pkts > 0, df['pkts_fwd'] / total_pkts, 0)
    total_bytes = df['bytes_fwd'] + df['bytes_rev']
    df['byte_ratio'] = np.where(total_bytes > 0, df['bytes_fwd'] / total_bytes, 0)

    # Zero-fill 21 fingerprint/source_stats (matches inline scoring behavior)
    for col in FINGERPRINT_COLS + SOURCE_STATS_COLS:
        df[col] = 0

    # Shuffle
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    # Stats
    feat_cols = [c for c in df.columns if c not in ['actor_id', 'label', 'label_confidence']]
    n_evil = int((df['label'] == 1).sum())
    n_clean = int((df['label'] == 5).sum())
    print(f'\nLabel distribution: EVIL={n_evil:,}  CLEAN={n_clean:,}  ratio=1:{n_clean / n_evil:.2f}')
    print(f'Features: {len(feat_cols)}')
    print(f'Feature names: {feat_cols}')

    out_path = os.path.join(DATA_DIR, 'evil_01_training.csv')
    print(f'\nWriting {out_path} ...')
    df.to_csv(out_path, index=False)
    size_mb = os.path.getsize(out_path) / 1e6
    print(f'Done: {len(df):,} rows, {size_mb:.0f} MB')
    print(f'\nTrain command:')
    print(f'  python3 -u /nvme0n1-disk/ml/train_xgb.py {out_path} --folds 5 --gpu --evil --scale-pos-weight 1.0')


if __name__ == '__main__':
    main()
