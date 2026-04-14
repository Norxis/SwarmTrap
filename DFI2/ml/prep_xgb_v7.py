#!/usr/bin/env python3
"""Prepare XGB v7 training CSV from clean norm + attack flow CSVs.

Combines norm_flows_clean.csv (label=5) + attack_flows.csv (label=1),
computes derived features, adds 21 zero-filled fingerprint/source_stats
to match v6's 75-feature schema, and writes a single training CSV.
"""
import os
import numpy as np
import pandas as pd

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

DROP_COLS = ['src_ip', 'dst_ip', 'src_port', 'vlan_id', 'first_ts', 'last_ts', 'capture_depth', 'ingested_at']

FINGERPRINT_COLS = [
    'ja3_freq', 'tls_version', 'tls_cipher_count', 'tls_ext_count', 'tls_has_sni',
    'hassh_freq', 'ssh_kex_count',
    'http_method', 'http_uri_len', 'http_header_count', 'http_ua_freq', 'http_has_body', 'http_status',
    'dns_qtype', 'dns_qname_len',
]
SOURCE_STATS_COLS = [
    'src_flow_count', 'src_unique_ports', 'src_unique_protos', 'src_unique_dsts', 'src_span_min', 'src_avg_pps',
]


def main():
    norm_path = os.path.join(DATA_DIR, 'norm_flows_clean.csv')
    attack_path = os.path.join(DATA_DIR, 'attack_flows.csv')
    out_path = os.path.join(DATA_DIR, 'xgb_v7_training.csv')

    print('Reading norm_flows_clean.csv ...')
    norm = pd.read_csv(norm_path, engine='pyarrow')
    norm['label'] = 5
    norm['label_confidence'] = 1.0
    print(f'  Norm: {len(norm):,} rows')

    print('Reading attack_flows.csv ...')
    attack = pd.read_csv(attack_path, engine='pyarrow')
    attack['label'] = 1
    attack['label_confidence'] = 1.0
    print(f'  Attack: {len(attack):,} rows')

    df = pd.concat([norm, attack], ignore_index=True)
    del norm, attack
    print(f'Combined: {len(df):,} rows')

    # Drop non-feature columns
    df.drop(columns=[c for c in DROP_COLS if c in df.columns], inplace=True)

    # Compute 4 derived features (matching v_xgb)
    df['bytes_per_pkt_fwd'] = np.where(df['pkts_fwd'] > 0, df['bytes_fwd'] / df['pkts_fwd'], 0)
    df['bytes_per_pkt_rev'] = np.where(df['pkts_rev'] > 0, df['bytes_rev'] / df['pkts_rev'], 0)
    total_pkts = df['pkts_fwd'] + df['pkts_rev']
    df['pkt_ratio'] = np.where(total_pkts > 0, df['pkts_fwd'] / total_pkts, 0)
    total_bytes = df['bytes_fwd'] + df['bytes_rev']
    df['byte_ratio'] = np.where(total_bytes > 0, df['bytes_fwd'] / total_bytes, 0)

    # Add 21 zero-filled fingerprint/source_stats (matches inline scoring behavior)
    for col in FINGERPRINT_COLS + SOURCE_STATS_COLS:
        df[col] = 0

    # Shuffle
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    # Stats
    n_norm = (df['label'] == 5).sum()
    n_attack = (df['label'] == 1).sum()
    spw = n_norm / n_attack if n_attack > 0 else 1.0
    feat_cols = [c for c in df.columns if c not in ['flow_id', 'session_key', 'actor_id', 'label', 'label_confidence']]
    print(f'\nLabel distribution: NORM={n_norm:,}  ATTACK={n_attack:,}')
    print(f'scale_pos_weight = {spw:.4f}')
    print(f'Features: {len(feat_cols)}')
    print(f'Total columns: {len(df.columns)}')

    print(f'\nWriting {out_path} ...')
    df.to_csv(out_path, index=False)
    size_mb = os.path.getsize(out_path) / 1e6
    print(f'Done: {len(df):,} rows, {size_mb:.0f} MB')
    print(f'\nTrain command:')
    print(f'  python3 -u train_xgb.py {out_path} --folds 5 --scale-pos-weight {spw:.4f}')


if __name__ == '__main__':
    main()
