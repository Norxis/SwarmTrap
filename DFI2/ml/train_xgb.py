#!/usr/bin/env python3
# Updated for combined 722-col dataset (XGB+CNN in one row)
import argparse
import json
import os
import time

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GroupKFold

OUTPUT_DIR = os.environ.get('ML_OUTPUT_DIR', '/mnt/dfi-data/ml/models')
TARGET = 'label'

# All 75 XGB feature columns from the combined 722-col dataset.
# src_* are REAL values from dfi.source_stats — no zero-fill needed.
XGB_FEAT_COLS = [
    'dst_port', 'ip_proto', 'app_proto',
    'pkts_fwd', 'pkts_rev', 'bytes_fwd', 'bytes_rev',
    'bytes_per_pkt_fwd', 'bytes_per_pkt_rev', 'pkt_ratio', 'byte_ratio',
    'duration_ms', 'rtt_ms', 'iat_fwd_mean_ms', 'iat_fwd_std_ms',
    'think_time_mean_ms', 'think_time_std_ms', 'iat_to_rtt', 'pps', 'bps', 'payload_rtt_ratio',
    'n_events', 'fwd_size_mean', 'fwd_size_std', 'fwd_size_min', 'fwd_size_max',
    'rev_size_mean', 'rev_size_std', 'rev_size_max',
    'hist_tiny', 'hist_small', 'hist_medium', 'hist_large', 'hist_full', 'frac_full',
    'syn_count', 'fin_count', 'rst_count', 'psh_count', 'ack_only_count',
    'conn_state', 'rst_frac', 'syn_to_data', 'psh_burst_max', 'retransmit_est', 'window_size_init',
    'entropy_first', 'entropy_fwd_mean', 'entropy_rev_mean',
    'printable_frac', 'null_frac', 'byte_std', 'high_entropy_frac', 'payload_len_first',
    'ja3_freq', 'tls_version', 'tls_cipher_count', 'tls_ext_count', 'tls_has_sni',
    'hassh_freq', 'ssh_kex_count',
    'http_method', 'http_uri_len', 'http_header_count', 'http_ua_freq', 'http_has_body', 'http_status',
    'dns_qtype', 'dns_qname_len',
    'src_flow_count', 'src_unique_ports', 'src_unique_protos', 'src_unique_dsts', 'src_span_min', 'src_avg_pps',
]

# Columns to drop from combined parquet (identity, labels, sequences) — not features
_DROP_PREFIXES = ('size_dir_seq_', 'tcp_flags_seq_', 'iat_log_ms_seq_', 'iat_rtt_bin_seq_', 'entropy_bin_seq_')
_DROP_NAMES = {'flow_id', 'session_key', 'actor_id', 'label', 'label_confidence',
               'evidence_mask', 'evidence_detail', '_rn',
               # Legacy pkt_ array columns (CSV format)
               'pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy',
               # Legacy ambiguous ClickHouse prefixed names
               'f.flow_id'}


def train(csv_path: str, n_splits: int = 5, output_dir: str = OUTPUT_DIR,
          recon: bool = False, evil: bool = False, evidence: bool = False,
          scale_pos_weight: float = 1.0, gpu: bool = False):
    if evidence:
        label_names = ['CLEAN', 'EVIDENCE']
        model_prefix = 'evidence'
        model_tag = 'evidence_01'
    elif evil:
        label_names = ['CLEAN', 'EVIL']
        model_prefix = 'evil'
        model_tag = 'evil_01'
    elif recon:
        label_names = ['NORM', 'RECON']
        model_prefix = 'xgb_recon'
        model_tag = 'xgb_recon_vs_norm'
    else:
        label_names = ['NORM', 'ATTACK']
        model_prefix = 'xgb'
        model_tag = 'xgb_v4_attack_vs_norm'
    nthread = 72 if gpu else 80

    # Load combined parquet or legacy CSV
    if csv_path.endswith('.parquet'):
        df = pd.read_parquet(csv_path)
    else:
        df = pd.read_csv(csv_path, engine='pyarrow', na_values=[r'\N'])
    # Rename any ClickHouse ambiguity-prefixed columns (legacy CSV)
    df.columns = [c.replace('f.', '') for c in df.columns]

    # Select the 75 XGB feature columns — drop identity/labels/sequences automatically.
    # Use XGB_FEAT_COLS if all present; fall back to dynamic detection for legacy CSVs.
    available_xgb = [c for c in XGB_FEAT_COLS if c in df.columns]
    if len(available_xgb) == len(XGB_FEAT_COLS):
        feat_cols = available_xgb
    else:
        # Legacy CSV: exclude identity, meta, pkt array, and sequence columns
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
    X = df[feat_cols]
    y_raw = df[TARGET].values
    # Binary: ATTACK (labels 1,2,3) → 1, NORM (label 5) → 0
    y = np.where(y_raw == 5, 0, 1).astype(np.int32)
    # For GroupKFold: norm flows all share actor_id="norm" — split them into
    # random sub-groups so they distribute evenly across folds
    groups = df['actor_id'].copy()
    norm_mask = groups == 'norm'
    if norm_mask.any():
        rng = np.random.RandomState(42)
        groups.loc[norm_mask] = [f'norm_{rng.randint(0, 1000)}' for _ in range(norm_mask.sum())]
    groups = groups.values
    weights = df['label_confidence'].fillna(0.5).values

    params = {
        'objective': 'binary:logistic',
        'max_depth': 8,
        'learning_rate': 0.05,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'min_child_weight': 5,
        'tree_method': 'hist',
        'max_bin': 512,
        'grow_policy': 'lossguide',
        'nthread': nthread,
        'eval_metric': 'logloss',
        'verbosity': 1,
    }
    if gpu:
        params['device'] = 'cuda'
    if scale_pos_weight != 1.0:
        params['scale_pos_weight'] = scale_pos_weight

    gkf = GroupKFold(n_splits=n_splits)
    fold_metrics = []
    best_model = None
    best_loss = float('inf')

    for fi, (tr, va) in enumerate(gkf.split(X, y, groups=groups), start=1):
        dtr = xgb.DMatrix(X.iloc[tr], label=y[tr], weight=weights[tr], enable_categorical=False, nthread=nthread)
        dva = xgb.DMatrix(X.iloc[va], label=y[va], weight=weights[va], enable_categorical=False, nthread=nthread)
        model = xgb.train(params, dtr, num_boost_round=3000, evals=[(dtr, 'train'), (dva, 'val')], early_stopping_rounds=75, verbose_eval=50)
        y_prob = model.predict(dva)
        y_pred = (y_prob > 0.5).astype(int)
        rep = classification_report(
            y[va],
            y_pred,
            labels=[0, 1],
            target_names=label_names,
            output_dict=True,
            zero_division=0,
        )
        cm = confusion_matrix(y[va], y_pred)
        val_loss = float(model.best_score)
        fold_metrics.append({'fold': fi, 'val_logloss': val_loss, 'accuracy': rep['accuracy'], 'macro_f1': rep['macro avg']['f1-score'], 'weighted_f1': rep['weighted avg']['f1-score'], 'confusion_matrix': cm.tolist()})
        print(f'  Fold {fi}: val_logloss={val_loss:.6f}  macro_f1={rep["macro avg"]["f1-score"]:.4f}  acc={rep["accuracy"]:.4f}')
        if val_loss < best_loss:
            best_loss = val_loss
            best_model = model

    dfull = xgb.DMatrix(X, label=y, weight=weights, enable_categorical=False, nthread=nthread)
    final_model = xgb.train(params, dfull, num_boost_round=(best_model.best_iteration + 1 if best_model else 200))

    os.makedirs(output_dir, exist_ok=True)
    ts = time.strftime('%Y%m%d_%H%M%S')
    model_path = os.path.join(output_dir, f'{model_prefix}_{ts}.json')
    metrics_path = os.path.join(output_dir, f'{model_prefix}_{ts}_metrics.json')
    final_model.save_model(model_path)

    with open(metrics_path, 'w', encoding='utf-8') as f:
        json.dump({'model': model_tag, 'timestamp': ts, 'n_samples': len(df), 'n_features': len(feat_cols), 'feature_names': feat_cols, 'params': params, 'best_iteration': int(best_model.best_iteration if best_model else 0), 'folds': fold_metrics, 'label_distribution': {label_names[i]: int((y == i).sum()) for i in range(2)}}, f, indent=2)

    print(model_path)
    return model_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('csv')
    ap.add_argument('--folds', type=int, default=5)
    ap.add_argument('--output', '-o', default=OUTPUT_DIR)
    ap.add_argument('--recon', action='store_true', help='RECON vs NORM labels (default: ATTACK vs NORM)')
    ap.add_argument('--evil', action='store_true', help='EVIL vs CLEAN binary classifier')
    ap.add_argument('--evidence', action='store_true', help='EVIDENCE (attack+recon only) vs CLEAN classifier')
    ap.add_argument('--gpu', action='store_true', help='Use CUDA GPU for training (device=cuda)')
    ap.add_argument('--scale-pos-weight', type=float, default=1.0, help='Weight multiplier for positive class (default: 1.0)')
    args = ap.parse_args()
    train(args.csv, args.folds, args.output, recon=args.recon, evil=args.evil, evidence=args.evidence,
          scale_pos_weight=args.scale_pos_weight, gpu=args.gpu)


if __name__ == '__main__':
    main()
