#!/usr/bin/env python3
"""Prepare evidence_01 training CSV: EVIDENCE (attack+recon) vs CLEAN.

Sources: attack.csv + recon.csv only — no dirty/watchlist data.
Balance: 1:1 (downsample clean to match evil count).
Weights: attack=5.0 (evidence-confirmed), recon=2.0 (honeypot), clean=1.0.
Train with: --evil --scale-pos-weight 5.0 --gpu
Output: 75 features matching XGB v7 inline scoring profile.
"""
import os
import numpy as np
import pandas as pd

DATA_DIR = '/nvme0n1-disk/ml/data'

DROP_COLS = [
    'flow_id', 'session_key', 'src_ip', 'dst_ip', 'src_port', 'vlan_id',
    'first_ts', 'last_ts', 'capture_depth', 'ingested_at',
    'pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy',
    'ja3_hash', 'hassh_hash', 'http_ua_hash',
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
    print('=== prep_evidence_01: EVIDENCE (attack+recon) vs CLEAN balanced ===\n')

    print('Reading attack.csv ...')
    attack = pd.read_csv(os.path.join(DATA_DIR, 'attack.csv'), engine='pyarrow')
    print(f'  {len(attack):,} rows')

    print('Reading recon.csv ...')
    recon = pd.read_csv(os.path.join(DATA_DIR, 'recon.csv'), engine='pyarrow')
    print(f'  {len(recon):,} rows')

    print('Reading clean.csv ...')
    clean = pd.read_csv(os.path.join(DATA_DIR, 'clean.csv'), engine='pyarrow')
    print(f'  {len(clean):,} rows')

    # Labels: evidence=1, clean=5 (train_xgb maps 5→0, else→1)
    # Per-sample weights: attack=5 (confirmed), recon=2 (honeypot), clean=1
    attack['label'] = 1
    attack['label_confidence'] = 5.0
    recon['label'] = 1
    recon['label_confidence'] = 2.0
    clean['label'] = 5
    clean['label_confidence'] = 1.0

    evil = pd.concat([attack, recon], ignore_index=True)
    del attack, recon
    print(f'\nEvidence total: {len(evil):,} rows  (attack + recon, no dirty)')
    print(f'Clean total:    {len(clean):,} rows')

    # Balance 1:1 — downsample the larger side
    n = min(len(evil), len(clean))
    if len(evil) > n:
        evil = evil.sample(n=n, random_state=42)
    if len(clean) > n:
        clean = clean.sample(n=n, random_state=42)
    print(f'Balanced: {n:,} evidence + {n:,} clean = {n * 2:,} total')

    df = pd.concat([evil, clean], ignore_index=True)
    del evil, clean

    # Drop unwanted columns
    df.drop(columns=[c for c in DROP_COLS if c in df.columns], inplace=True)

    # Derived features (matches v_xgb view / inline scoring)
    df['bytes_per_pkt_fwd'] = np.where(df['pkts_fwd'] > 0, df['bytes_fwd'] / df['pkts_fwd'], 0)
    df['bytes_per_pkt_rev'] = np.where(df['pkts_rev'] > 0, df['bytes_rev'] / df['pkts_rev'], 0)
    total_pkts = df['pkts_fwd'] + df['pkts_rev']
    df['pkt_ratio'] = np.where(total_pkts > 0, df['pkts_fwd'] / total_pkts, 0)
    total_bytes = df['bytes_fwd'] + df['bytes_rev']
    df['byte_ratio'] = np.where(total_bytes > 0, df['bytes_fwd'] / total_bytes, 0)

    # Zero-fill fingerprint/source_stats (matches inline scoring behavior)
    for col in FINGERPRINT_COLS + SOURCE_STATS_COLS:
        df[col] = 0

    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    feat_cols = [c for c in df.columns if c not in ['actor_id', 'label', 'label_confidence']]
    n_pos = int((df['label'] == 1).sum())
    n_neg = int((df['label'] == 5).sum())
    print(f'\nLabel distribution: EVIDENCE={n_pos:,}  CLEAN={n_neg:,}  ratio=1:{n_neg / n_pos:.2f}')
    print(f'Features: {len(feat_cols)}')
    print(f'Feature names: {feat_cols}')

    out_path = os.path.join(DATA_DIR, 'evidence_01_training.csv')
    print(f'\nWriting {out_path} ...')
    df.to_csv(out_path, index=False)
    size_mb = os.path.getsize(out_path) / 1e6
    print(f'Done: {len(df):,} rows, {size_mb:.0f} MB')
    print(f'\nTrain command:')
    print(f'  python3 -u /nvme0n1-disk/ml/train_xgb.py {out_path} --folds 5 --gpu --evidence --scale-pos-weight 5.0 --output /nvme0n1-disk/ml/models')


if __name__ == '__main__':
    main()
