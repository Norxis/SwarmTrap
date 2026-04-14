#!/usr/bin/env python3
"""Score flows using 3-class XGB model: RECON(0) vs ATTACK(1) vs CLEAN(2).

Usage:
    python3 score_3class.py model.json input.csv -o scored.csv
    python3 score_3class.py model.json input.csv -o scored.csv --summary
"""
import argparse
import json
import os
import time

import numpy as np
import pandas as pd
import xgboost as xgb

CLASS_NAMES = ['RECON', 'ATTACK', 'CLEAN']

_DROP_NAMES = {
    'flow_id', 'session_key', 'actor_id', 'label', 'label_confidence',
    'evidence_mask', 'evidence_detail', '_rn',
    'pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy',
    'size_dir_arr', 'tcp_flags_arr', 'iat_log_ms_arr', 'iat_rtt_bin_arr', 'entropy_bin_arr',
    'src_ip', 'dst_ip', 'src_port', 'first_ts', 'last_ts', 'ingested_at',
    'capture_depth', 'vlan_id', 'f.flow_id',
}
_DROP_PREFIXES = ('size_dir_seq_', 'tcp_flags_seq_', 'iat_log_ms_seq_', 'iat_rtt_bin_seq_', 'entropy_bin_seq_')


def main():
    ap = argparse.ArgumentParser(description='Score flows with 3-class XGB')
    ap.add_argument('model', help='XGB model JSON path')
    ap.add_argument('csv', help='Input CSV to score')
    ap.add_argument('-o', '--output', help='Output CSV path (scored)')
    ap.add_argument('--summary', action='store_true', help='Print class distribution summary')
    args = ap.parse_args()

    t0 = time.time()

    # Load model
    bst = xgb.Booster()
    bst.load_model(args.model)
    model_features = bst.feature_names
    print(f'Model: {args.model} ({len(model_features)} features)', flush=True)

    # Load data
    df = pd.read_csv(args.csv, engine='pyarrow', na_values=[r'\N', 'NULL'])
    df.columns = [c.replace('f.', '') for c in df.columns]
    df = df.loc[:, ~df.columns.duplicated()]
    print(f'Loaded {len(df):,} rows, {len(df.columns)} cols', flush=True)

    # Build feature matrix matching model's feature names
    X = np.zeros((len(df), len(model_features)), dtype=np.float32)
    matched = 0
    for i, feat in enumerate(model_features):
        if feat in df.columns:
            vals = pd.to_numeric(df[feat], errors='coerce').fillna(0).values
            X[:, i] = vals
            matched += 1
    print(f'Matched {matched}/{len(model_features)} features', flush=True)

    # Score
    dmat = xgb.DMatrix(X, feature_names=model_features)
    probs = bst.predict(dmat)
    pred_labels = np.argmax(probs, axis=1)
    pred_conf = np.max(probs, axis=1)

    # Add predictions to dataframe
    df['pred_label'] = pred_labels
    df['pred_confidence'] = pred_conf.round(4)
    df['pred_class'] = [CLASS_NAMES[l] for l in pred_labels]

    # Summary
    print(f'\nPrediction distribution:')
    for i, name in enumerate(CLASS_NAMES):
        n = (pred_labels == i).sum()
        avg_conf = pred_conf[pred_labels == i].mean() if n > 0 else 0
        print(f'  {i} ({name}): {n:,} ({n/len(df)*100:.1f}%) avg_conf={avg_conf:.3f}')

    if args.summary:
        # High confidence breakdown
        for thresh in [0.9, 0.95, 0.99]:
            high = pred_conf >= thresh
            print(f'\n  Confidence >= {thresh}: {high.sum():,} ({high.sum()/len(df)*100:.1f}%)')
            for i, name in enumerate(CLASS_NAMES):
                n = ((pred_labels == i) & high).sum()
                if n > 0:
                    print(f'    {name}: {n:,}')

    # Save
    if args.output:
        df.to_csv(args.output, index=False)
        print(f'\nSaved: {args.output}')

    elapsed = time.time() - t0
    print(f'Total: {elapsed:.0f}s', flush=True)


if __name__ == '__main__':
    main()
