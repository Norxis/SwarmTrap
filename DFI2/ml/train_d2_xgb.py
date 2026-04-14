#!/usr/bin/env python3
"""XGB training from D2 capture data (ip_capture_d2).

Copied from proven train_5class.py. Binary classification: ATTACK(0) vs CLEAN(1).
Input: merged CSV/parquet with 'label' column (0=attack, 1=clean).

Usage:
    python3 train_d2_xgb.py training_d2.parquet --folds 5 --gpu -o models/d2_v1
"""
import argparse
import json
import os
import time

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GroupKFold

OUTPUT_DIR = os.environ.get('ML_OUTPUT_DIR', '/nvme0n1-disk/ml/models')
TARGET = 'label'
NUM_CLASSES = 2
CLASS_NAMES = ['ATTACK', 'CLEAN']

# Columns to drop (identity, meta, pkt arrays as strings, non-feature columns)
_DROP_NAMES = {
    'label', 'label_confidence', 'truth_label',
    'discrepancy_type', 'verdict_group',
    'src_ip', 'dst_ip', 'first_ts', 'last_ts', 'captured_at', 'ingested_at',
    'sensor', 'evidence_mask',
    # CNN arrays (string columns — not for XGB)
    'pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy',
    'first_fwd_payload',
    # XGB output (from capture — we're retraining, don't use old model output as feature)
    'xgb_class', 'xgb_confidence', 'xgb_probs',
    # Capture metadata
    'capture_value_score', 'service_id', 'service_class',
}
_DROP_PREFIXES = ('size_dir_seq_', 'tcp_flags_seq_', 'iat_log_ms_seq_', 'iat_rtt_bin_seq_', 'entropy_bin_seq_')


def train(data_path, n_splits=5, output_dir=OUTPUT_DIR, gpu=False):
    nthread = 72
    t0 = time.time()

    # Load — pyarrow engine handles \N at read time
    if data_path.endswith('.parquet'):
        df = pd.read_parquet(data_path)
    else:
        df = pd.read_csv(data_path, engine='pyarrow', na_values=[r'\N', 'NULL'])
    # Deduplicate columns (safety)
    df = df.loc[:, ~df.columns.duplicated()]
    print(f'Loaded {len(df):,} rows, {len(df.columns)} cols ({time.time()-t0:.0f}s)', flush=True)

    # Class distribution
    print('\nClass distribution:')
    for lbl in sorted(df[TARGET].unique()):
        n = (df[TARGET] == lbl).sum()
        name = CLASS_NAMES[lbl] if lbl < len(CLASS_NAMES) else f'UNK_{lbl}'
        print(f'  {lbl} ({name}): {n:,}')

    # Feature columns — auto-detect, exclude identity/meta/arrays
    feat_cols = [
        c for c in df.columns
        if c not in _DROP_NAMES
        and not any(c.startswith(p) for p in _DROP_PREFIXES)
        and c != TARGET
    ]
    # Coerce any remaining object cols to numeric
    for c in feat_cols:
        if df[c].dtype == object:
            df[c] = pd.to_numeric(df[c], errors='coerce')
    print(f'Features: {len(feat_cols)}', flush=True)
    print(f'Sample features: {feat_cols[:10]}', flush=True)

    X = df[feat_cols]
    y = df[TARGET].values.astype(np.int32)

    # GroupKFold by src_ip — prevents same IP in both train and val
    if 'src_ip' in df.columns:
        groups = df['src_ip'].fillna('unknown').values
    else:
        groups = np.arange(len(df))

    params = {
        'objective': 'multi:softprob',
        'num_class': NUM_CLASSES,
        'eval_metric': 'mlogloss',
        'max_depth': 8,
        'learning_rate': 0.05,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'min_child_weight': 5,
        'tree_method': 'hist',
        'max_bin': 512,
        'grow_policy': 'lossguide',
        'nthread': nthread,
        'verbosity': 1,
    }
    if gpu:
        params['device'] = 'cuda'

    gkf = GroupKFold(n_splits=n_splits)
    fold_metrics = []
    best_model = None
    best_loss = float('inf')

    for fi, (tr, va) in enumerate(gkf.split(X, y, groups=groups), start=1):
        ft = time.time()
        print(f'\n=== Fold {fi}/{n_splits} (train={len(tr):,} val={len(va):,}) ===', flush=True)

        dtr = xgb.DMatrix(X.iloc[tr], label=y[tr], enable_categorical=False, nthread=nthread)
        dva = xgb.DMatrix(X.iloc[va], label=y[va], enable_categorical=False, nthread=nthread)

        model = xgb.train(
            params, dtr,
            num_boost_round=10000,
            evals=[(dtr, 'train'), (dva, 'val')],
            early_stopping_rounds=75,
            verbose_eval=50,
        )

        y_prob = model.predict(dva)
        y_pred = np.argmax(y_prob, axis=1)
        rep = classification_report(
            y[va], y_pred,
            labels=list(range(NUM_CLASSES)),
            target_names=CLASS_NAMES,
            output_dict=True,
            zero_division=0,
        )
        cm = confusion_matrix(y[va], y_pred)
        val_loss = float(model.best_score)

        fold_metrics.append({
            'fold': fi,
            'val_mlogloss': val_loss,
            'accuracy': rep['accuracy'],
            'macro_f1': rep['macro avg']['f1-score'],
            'weighted_f1': rep['weighted avg']['f1-score'],
            'confusion_matrix': cm.tolist(),
        })

        print(f'  Fold {fi}: mlogloss={val_loss:.4f}  acc={rep["accuracy"]:.4f}  '
              f'macro_f1={rep["macro avg"]["f1-score"]:.4f}  ({time.time()-ft:.0f}s)', flush=True)
        print(classification_report(y[va], y_pred, target_names=CLASS_NAMES, digits=4), flush=True)

        if val_loss < best_loss:
            best_loss = val_loss
            best_model = model

    # Train final model on all data
    print('\n=== Training final model on all data ===', flush=True)
    dfull = xgb.DMatrix(X, label=y, enable_categorical=False, nthread=nthread)
    final_rounds = best_model.best_iteration + 1 if best_model else 500
    final_model = xgb.train(params, dfull, num_boost_round=final_rounds)

    # Save
    os.makedirs(output_dir, exist_ok=True)
    ts = time.strftime('%Y%m%d_%H%M%S')
    model_path = os.path.join(output_dir, f'd2_xgb_{ts}.json')
    metrics_path = os.path.join(output_dir, f'd2_xgb_{ts}_metrics.json')
    final_model.save_model(model_path)

    # Feature importance
    imp = final_model.get_score(importance_type='gain')
    top20 = sorted(imp.items(), key=lambda x: -x[1])[:20]
    print('\nTop 20 features (gain):')
    for feat, score in top20:
        print(f'  {feat}: {score:.1f}')

    meta = {
        'model': 'd2_xgb_v1',
        'timestamp': ts,
        'classes': CLASS_NAMES,
        'n_samples': len(df),
        'n_features': len(feat_cols),
        'feature_names': feat_cols,
        'params': params,
        'best_iteration': int(best_model.best_iteration if best_model else 0),
        'folds': fold_metrics,
        'label_distribution': {CLASS_NAMES[i]: int((y == i).sum()) for i in range(NUM_CLASSES)},
    }
    with open(metrics_path, 'w') as f:
        json.dump(meta, f, indent=2)

    elapsed = time.time() - t0
    print(f'\nSaved: {model_path}')
    print(f'Total time: {elapsed:.0f}s ({elapsed/60:.1f}min)')
    return model_path


def main():
    ap = argparse.ArgumentParser(description='D2 XGB: ATTACK vs CLEAN')
    ap.add_argument('data', help='Training CSV or parquet')
    ap.add_argument('--folds', type=int, default=5)
    ap.add_argument('-o', '--output', default=OUTPUT_DIR)
    ap.add_argument('--gpu', action='store_true', help='Use CUDA GPU')
    args = ap.parse_args()
    train(args.data, args.folds, args.output, gpu=args.gpu)


if __name__ == '__main__':
    main()
