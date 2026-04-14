# Phase 9: ML Pipelines

> **Executor:** Codex
> **Reviewer:** Claude Code
> **Status:** Not started
> **Depends on:** Phase 7 (labels exist for training data)

## Objective

Build the ML training pipelines: ClickHouse → CSV export, XGBoost training (75 features, 5 classes, GroupKFold), CNN training (5-channel × 128 + 42 static, PyTorch), and model scoring (predictions → ClickHouse).

## Reference Files

| File | What to read |
|------|-------------|
| `~/ai-shared/DFI2/DFI2_XGB_v1_Spec.md` | Full 75-feature spec, XGBoost parameters, GroupKFold, confidence weighting |
| `~/ai-shared/DFI2/DFI2_CNN_v1_Spec.md` | 5-channel × 128 positions, 42 static features, DFI_CNN model architecture, training tips |
| `~/ai-shared/DFI2/DFI2_Dataset_DB_Spec.md` | Export views: `v_xgb` (lines 849-951), `v_cnn_sequences` (lines 984-1064), `model_predictions` table (lines 428-461) |

## Output Files

```
~/DFI2/ml/
├── __init__.py
├── export.py          # CH → CSV (XGBoost 82-col + CNN 689-col)
├── train_xgb.py       # XGBoost multi:softprob, 5 classes, GroupKFold
├── train_cnn.py       # PyTorch DFI_CNN (5ch × 128 + 42 static → 5 classes)
└── score.py           # Load model, score unscored flows → CH model_predictions
```

---

## Step 1: export.py — ClickHouse → CSV

```python
#!/usr/bin/env python3
"""export.py — Export training data from ClickHouse to CSV.

Usage:
    python export.py xgb                    # Full XGBoost export
    python export.py xgb --balanced 1000    # 1000 per class
    python export.py xgb --min-conf 0.8     # High confidence only
    python export.py cnn                    # Full CNN export
    python export.py cnn --balanced 500     # 500 per class
"""

import argparse
import csv
import os
import sys
import time

from clickhouse_driver import Client

CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))
OUTPUT_DIR = os.environ.get('ML_OUTPUT_DIR', '/opt/dfi2/ml/data')
SEQ_LEN = 128
CHANNELS = ['size_dir_seq', 'tcp_flags_seq', 'iat_log_ms_seq',
            'iat_rtt_bin_seq', 'entropy_bin_seq']


def export_xgb(ch: Client, output: str, balanced: int = 0, min_conf: float = 0.0,
               hours: int = 0):
    """Export XGBoost training data (82 columns)."""
    query = "SELECT * FROM dfi.v_xgb"
    conditions = []

    if min_conf > 0:
        conditions.append(f"label_confidence >= {min_conf}")
    if hours > 0:
        conditions.append(f"flow_id IN (SELECT flow_id FROM dfi.flows WHERE first_ts >= now() - INTERVAL {hours} HOUR)")

    if balanced > 0:
        # Balanced sampling: N per class
        base_query = query
        if conditions:
            base_query += " WHERE " + " AND ".join(conditions)
        query = f"""
            SELECT * FROM (
                SELECT *, row_number() OVER (PARTITION BY label ORDER BY rand()) AS _rn
                FROM ({base_query})
            ) WHERE _rn <= {balanced}
        """
    elif conditions:
        query += " WHERE " + " AND ".join(conditions)

    print(f"Exporting XGBoost data...")
    start = time.time()

    # Get column names
    meta = ch.execute("SELECT * FROM dfi.v_xgb LIMIT 0", with_column_types=True)
    col_names = [c[0] for c in meta[1]]

    # Fetch data
    rows = ch.execute(query)

    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    with open(output, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(col_names)
        for row in rows:
            w.writerow(row)

    elapsed = time.time() - start
    print(f"Exported {len(rows)} rows to {output} ({elapsed:.1f}s)")
    print(f"Columns: {len(col_names)}")

    # Print label distribution
    from collections import Counter
    label_idx = col_names.index('label')
    dist = Counter(row[label_idx] for row in rows)
    NAMES = {0: 'RECON', 1: 'KNOCK', 2: 'BRUTEFORCE', 3: 'EXPLOIT', 4: 'COMPROMISE'}
    for k in sorted(dist):
        print(f"  {NAMES.get(k, k)}: {dist[k]}")


def export_cnn(ch: Client, output: str, balanced: int = 0, min_conf: float = 0.0,
               hours: int = 0):
    """Export CNN training data (689 columns).

    Joins v_xgb (static features + labels) with v_cnn_sequences (5-channel tokens).
    """
    print(f"Exporting CNN data...")
    start = time.time()

    # Get XGBoost column names
    meta = ch.execute("SELECT * FROM dfi.v_xgb LIMIT 0", with_column_types=True)
    xgb_cols = [c[0] for c in meta[1]]

    ID_LABEL = ['flow_id', 'session_key', 'actor_id',
                'label', 'label_confidence', 'evidence_mask', 'evidence_detail']
    STATIC = [c for c in xgb_cols if c not in ID_LABEL]

    # Sequence column names
    seq_col_names = []
    for ch_name in CHANNELS:
        seq_col_names += [f'{ch_name}_{i}' for i in range(1, SEQ_LEN + 1)]

    header = ID_LABEL + seq_col_names + STATIC

    # Fetch sequences
    print("  Fetching packet sequences...")
    seq_data = ch.execute("SELECT * FROM dfi.v_cnn_sequences")
    seq_map = {}
    for row in seq_data:
        fid = row[0]
        arrs = {}
        for i, ch_name in enumerate(CHANNELS):
            a = list(row[i + 1])
            a += [0] * (SEQ_LEN - len(a))
            arrs[ch_name] = a[:SEQ_LEN]
        seq_map[fid] = arrs
    print(f"  {len(seq_map)} flows with sequences")

    # Fetch XGBoost data (static features + labels)
    print("  Fetching static features...")
    xgb_query = "SELECT * FROM dfi.v_xgb"
    conditions = []
    if min_conf > 0:
        conditions.append(f"label_confidence >= {min_conf}")
    if hours > 0:
        conditions.append(f"flow_id IN (SELECT flow_id FROM dfi.flows WHERE first_ts >= now() - INTERVAL {hours} HOUR)")

    if balanced > 0:
        base = xgb_query
        if conditions:
            base += " WHERE " + " AND ".join(conditions)
        xgb_query = f"""
            SELECT * FROM (
                SELECT *, row_number() OVER (PARTITION BY label ORDER BY rand()) AS _rn
                FROM ({base})
            ) WHERE _rn <= {balanced}
        """
    elif conditions:
        xgb_query += " WHERE " + " AND ".join(conditions)

    xgb_data = ch.execute(xgb_query)

    # Write combined CSV
    os.makedirs(os.path.dirname(output) or '.', exist_ok=True)
    written = 0
    with open(output, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(header)
        for xgb_row in xgb_data:
            rd = dict(zip(xgb_cols, xgb_row))
            fid = rd['flow_id']
            vals = [rd.get(c, '') for c in ID_LABEL]

            if fid in seq_map:
                for ch_name in CHANNELS:
                    vals.extend(seq_map[fid][ch_name])
            else:
                vals.extend([0] * SEQ_LEN * len(CHANNELS))

            vals.extend([rd.get(c, '') for c in STATIC])
            w.writerow(vals)
            written += 1

    elapsed = time.time() - start
    print(f"Exported {written} rows to {output} ({elapsed:.1f}s)")
    print(f"Columns: {len(header)} (7 identity + {SEQ_LEN * len(CHANNELS)} sequence + {len(STATIC)} static)")

    # Print label distribution
    from collections import Counter
    label_idx = xgb_cols.index('label')
    dist = Counter(row[label_idx] for row in xgb_data)
    NAMES = {0: 'RECON', 1: 'KNOCK', 2: 'BRUTEFORCE', 3: 'EXPLOIT', 4: 'COMPROMISE'}
    for k in sorted(dist):
        print(f"  {NAMES.get(k, k)}: {dist[k]}")


def main():
    parser = argparse.ArgumentParser(description='Export DFI2 training data from ClickHouse')
    parser.add_argument('format', choices=['xgb', 'cnn'], help='Export format')
    parser.add_argument('--output', '-o', help='Output CSV path')
    parser.add_argument('--balanced', type=int, default=0, help='Balanced sample N per class')
    parser.add_argument('--min-conf', type=float, default=0.0, help='Minimum label confidence')
    parser.add_argument('--hours', type=int, default=0, help='Only last N hours')
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ch = Client(CH_HOST, port=CH_PORT)

    if args.format == 'xgb':
        output = args.output or os.path.join(OUTPUT_DIR, 'dfi_xgb_v1.csv')
        export_xgb(ch, output, args.balanced, args.min_conf, args.hours)
    else:
        output = args.output or os.path.join(OUTPUT_DIR, 'dfi_cnn_v1.csv')
        export_cnn(ch, output, args.balanced, args.min_conf, args.hours)


if __name__ == '__main__':
    main()
```

---

## Step 2: train_xgb.py — XGBoost Training

```python
#!/usr/bin/env python3
"""train_xgb.py — Train XGBoost classifier on DFI2 data.

75 features → 5-class multi:softprob with GroupKFold by actor_id.
"""

import argparse
import json
import os
import time

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import GroupKFold
from sklearn.metrics import classification_report, confusion_matrix

OUTPUT_DIR = os.environ.get('ML_OUTPUT_DIR', '/opt/dfi2/ml/models')

LABEL_NAMES = ['RECON', 'KNOCK', 'BRUTEFORCE', 'EXPLOIT', 'COMPROMISE']

ID_COLS = ['flow_id', 'session_key', 'actor_id']
META_COLS = ['label_confidence', 'evidence_mask', 'evidence_detail']
TARGET = 'label'

# Categorical features for XGBoost
CAT_FEATURES = ['ip_proto', 'app_proto', 'conn_state', 'http_method', 'dns_qtype', 'tls_version']


def train(csv_path: str, n_splits: int = 5, output_dir: str = OUTPUT_DIR):
    print(f"Loading data from {csv_path}...")
    df = pd.read_csv(csv_path)
    print(f"  {len(df)} rows, {len(df.columns)} columns")

    # Separate features, labels, identity
    feat_cols = [c for c in df.columns if c not in ID_COLS + META_COLS + [TARGET]]
    print(f"  {len(feat_cols)} training features")

    X = df[feat_cols]
    y = df[TARGET].values
    groups = df['actor_id'].values
    weights = df['label_confidence'].values

    # Label distribution
    print("\nLabel distribution:")
    for i, name in enumerate(LABEL_NAMES):
        count = (y == i).sum()
        print(f"  {name}: {count} ({count/len(y)*100:.1f}%)")

    # XGBoost parameters (from spec)
    params = {
        'objective': 'multi:softprob',
        'num_class': 5,
        'max_depth': 8,
        'learning_rate': 0.05,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'min_child_weight': 5,
        'tree_method': 'hist',
        'eval_metric': 'mlogloss',
        'verbosity': 1,
    }

    # GroupKFold — same actor never in train + test
    gkf = GroupKFold(n_splits=n_splits)
    fold_metrics = []

    print(f"\nTraining {n_splits}-fold GroupKFold...")
    best_model = None
    best_logloss = float('inf')

    for fold_idx, (train_idx, val_idx) in enumerate(gkf.split(X, y, groups=groups)):
        print(f"\n--- Fold {fold_idx + 1}/{n_splits} ---")
        X_train, X_val = X.iloc[train_idx], X.iloc[val_idx]
        y_train, y_val = y[train_idx], y[val_idx]
        w_train, w_val = weights[train_idx], weights[val_idx]

        # DMatrix with confidence weighting
        dtrain = xgb.DMatrix(X_train, label=y_train, weight=w_train,
                              enable_categorical=False)
        dval = xgb.DMatrix(X_val, label=y_val, weight=w_val,
                            enable_categorical=False)

        model = xgb.train(
            params, dtrain,
            num_boost_round=500,
            evals=[(dtrain, 'train'), (dval, 'val')],
            early_stopping_rounds=50,
            verbose_eval=50,
        )

        # Predictions
        y_pred_probs = model.predict(dval)
        y_pred = np.argmax(y_pred_probs, axis=1)

        # Metrics
        report = classification_report(y_val, y_pred, target_names=LABEL_NAMES,
                                        output_dict=True, zero_division=0)
        cm = confusion_matrix(y_val, y_pred)
        val_logloss = model.best_score

        print(f"\nFold {fold_idx + 1} results:")
        print(classification_report(y_val, y_pred, target_names=LABEL_NAMES, zero_division=0))
        print(f"Confusion matrix:\n{cm}")

        fold_metrics.append({
            'fold': fold_idx + 1,
            'val_logloss': val_logloss,
            'accuracy': report['accuracy'],
            'macro_f1': report['macro avg']['f1-score'],
            'weighted_f1': report['weighted avg']['f1-score'],
        })

        if val_logloss < best_logloss:
            best_logloss = val_logloss
            best_model = model

    # Train final model on full data
    print("\n--- Training final model on all data ---")
    dfull = xgb.DMatrix(X, label=y, weight=weights, enable_categorical=False)
    final_model = xgb.train(params, dfull, num_boost_round=best_model.best_iteration + 1)

    # Save model + metrics
    os.makedirs(output_dir, exist_ok=True)
    timestamp = time.strftime('%Y%m%d_%H%M%S')

    model_path = os.path.join(output_dir, f'xgb_{timestamp}.json')
    final_model.save_model(model_path)
    print(f"\nModel saved: {model_path}")

    metrics_path = os.path.join(output_dir, f'xgb_{timestamp}_metrics.json')
    with open(metrics_path, 'w') as f:
        json.dump({
            'model': 'xgb_v1',
            'timestamp': timestamp,
            'n_samples': len(df),
            'n_features': len(feat_cols),
            'feature_names': feat_cols,
            'params': params,
            'best_iteration': best_model.best_iteration,
            'folds': fold_metrics,
            'label_distribution': {LABEL_NAMES[i]: int((y == i).sum()) for i in range(5)},
        }, f, indent=2, default=str)
    print(f"Metrics saved: {metrics_path}")

    # Feature importance
    importance = final_model.get_score(importance_type='gain')
    top_features = sorted(importance.items(), key=lambda x: -x[1])[:20]
    print("\nTop 20 features by gain:")
    for feat, gain in top_features:
        print(f"  {feat}: {gain:.1f}")

    return model_path


def main():
    parser = argparse.ArgumentParser(description='Train XGBoost on DFI2 data')
    parser.add_argument('csv', help='Path to XGBoost CSV export')
    parser.add_argument('--folds', type=int, default=5, help='Number of CV folds')
    parser.add_argument('--output', '-o', default=OUTPUT_DIR, help='Output directory')
    args = parser.parse_args()

    train(args.csv, args.folds, args.output)


if __name__ == '__main__':
    main()
```

---

## Step 3: train_cnn.py — PyTorch CNN Training

```python
#!/usr/bin/env python3
"""train_cnn.py — Train DFI_CNN on 5-channel packet sequences + 42 static features.

Architecture: 5-channel embeddings → Conv1D stack → concat static → Dense → 5-class softmax.
"""

import argparse
import json
import os
import time

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import GroupKFold
from sklearn.metrics import classification_report, confusion_matrix

OUTPUT_DIR = os.environ.get('ML_OUTPUT_DIR', '/opt/dfi2/ml/models')
LABEL_NAMES = ['RECON', 'KNOCK', 'BRUTEFORCE', 'EXPLOIT', 'COMPROMISE']
SEQ_LEN = 128


# --- Model Architecture (from CNN spec) ---

class DFI_CNN(nn.Module):
    def __init__(self, num_classes=5):
        super().__init__()

        # Sequence embeddings (one per channel)
        self.size_emb    = nn.Embedding(23, 12, padding_idx=0)   # [-11..+11] → offset +11
        self.flag_emb    = nn.Embedding(17,  6, padding_idx=0)
        self.iat_emb     = nn.Embedding( 9,  6, padding_idx=0)
        self.rtt_emb     = nn.Embedding(10,  6, padding_idx=0)
        self.entropy_emb = nn.Embedding( 7,  4, padding_idx=0)
        # Per-position: 12 + 6 + 6 + 6 + 4 = 34 dims

        # Conv1D stack (multi-kernel inception style)
        self.conv3 = nn.Sequential(
            nn.Conv1d(34, 32, kernel_size=3, padding=1),
            nn.BatchNorm1d(32), nn.ReLU(),
        )
        self.conv5 = nn.Sequential(
            nn.Conv1d(34, 32, kernel_size=5, padding=2),
            nn.BatchNorm1d(32), nn.ReLU(),
        )
        self.conv7 = nn.Sequential(
            nn.Conv1d(34, 32, kernel_size=7, padding=3),
            nn.BatchNorm1d(32), nn.ReLU(),
        )
        # After concat: 96 channels
        self.conv_merge = nn.Sequential(
            nn.Conv1d(96, 128, kernel_size=5, padding=2),
            nn.BatchNorm1d(128), nn.ReLU(),
            nn.AdaptiveMaxPool1d(1),  # → (batch, 128, 1)
        )

        # Static metadata branch
        self.static_bn = nn.BatchNorm1d(42)

        # Classifier head
        self.head = nn.Sequential(
            nn.Linear(128 + 42, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, num_classes),
        )

    def forward(self, size_seq, flag_seq, iat_seq, rtt_seq, ent_seq, static_feat):
        # Embeddings: (B, 128) → (B, 128, dim)
        s = self.size_emb(size_seq)
        f = self.flag_emb(flag_seq)
        i = self.iat_emb(iat_seq)
        r = self.rtt_emb(rtt_seq)
        e = self.entropy_emb(ent_seq)

        x = torch.cat([s, f, i, r, e], dim=2)  # (B, 128, 34)
        x = x.transpose(1, 2)                   # (B, 34, 128)

        # Mask padding positions
        mask = (size_seq != 0).unsqueeze(1).float()  # (B, 1, 128)
        x = x * mask

        # Inception-style multi-kernel
        c3 = self.conv3(x)
        c5 = self.conv5(x)
        c7 = self.conv7(x)
        x = torch.cat([c3, c5, c7], dim=1)  # (B, 96, 128)

        x = self.conv_merge(x).squeeze(2)  # (B, 128)

        # Static branch
        m = self.static_bn(static_feat)  # (B, 42)

        # Fuse and classify
        out = self.head(torch.cat([x, m], dim=1))  # (B, 5)
        return out


# --- Dataset ---

STATIC_COLS = [
    'dst_port', 'ip_proto', 'app_proto',
    'pkts_fwd', 'pkts_rev', 'bytes_fwd', 'bytes_rev',
    'bytes_per_pkt_fwd', 'bytes_per_pkt_rev', 'pkt_ratio', 'byte_ratio',
    'rtt_ms', 'n_events',
    'entropy_first', 'entropy_fwd_mean', 'entropy_rev_mean',
    'printable_frac', 'null_frac', 'byte_std', 'high_entropy_frac', 'payload_len_first',
    'ja3_freq', 'tls_version', 'tls_cipher_count', 'tls_ext_count', 'tls_has_sni',
    'hassh_freq', 'ssh_kex_count',
    'http_method', 'http_uri_len', 'http_header_count', 'http_ua_freq',
    'http_has_body', 'http_status',
    'dns_qtype', 'dns_qname_len',
    'src_flow_count', 'src_unique_ports', 'src_unique_protos',
    'src_unique_dsts', 'src_span_min', 'src_avg_pps',
]


class DFIDataset(Dataset):
    def __init__(self, df):
        # Sequence channels
        size_cols = [f'size_dir_seq_{i}' for i in range(1, SEQ_LEN + 1)]
        flag_cols = [f'tcp_flags_seq_{i}' for i in range(1, SEQ_LEN + 1)]
        iat_cols  = [f'iat_log_ms_seq_{i}' for i in range(1, SEQ_LEN + 1)]
        rtt_cols  = [f'iat_rtt_bin_seq_{i}' for i in range(1, SEQ_LEN + 1)]
        ent_cols  = [f'entropy_bin_seq_{i}' for i in range(1, SEQ_LEN + 1)]

        self.size_seq = torch.tensor(df[size_cols].fillna(0).values + 11, dtype=torch.long)
        self.flag_seq = torch.tensor(df[flag_cols].fillna(0).values, dtype=torch.long)
        self.iat_seq  = torch.tensor(df[iat_cols].fillna(0).values, dtype=torch.long)
        self.rtt_seq  = torch.tensor(df[rtt_cols].fillna(0).values, dtype=torch.long)
        self.ent_seq  = torch.tensor(df[ent_cols].fillna(0).values, dtype=torch.long)

        self.static = torch.tensor(
            df[STATIC_COLS].fillna(0).values.astype(np.float32), dtype=torch.float32
        )
        self.labels = torch.tensor(df['label'].values, dtype=torch.long)
        self.weights = torch.tensor(df['label_confidence'].fillna(0.5).values, dtype=torch.float32)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return (self.size_seq[idx], self.flag_seq[idx], self.iat_seq[idx],
                self.rtt_seq[idx], self.ent_seq[idx], self.static[idx],
                self.labels[idx], self.weights[idx])


# --- Training ---

def train_cnn(csv_path: str, epochs: int = 50, batch_size: int = 512,
              lr: float = 1e-3, n_splits: int = 5, output_dir: str = OUTPUT_DIR):
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Device: {device}")

    print(f"Loading data from {csv_path}...")
    df = pd.read_csv(csv_path)
    print(f"  {len(df)} rows, {len(df.columns)} columns")

    y = df['label'].values
    groups = df['actor_id'].values

    # Label distribution
    print("\nLabel distribution:")
    for i, name in enumerate(LABEL_NAMES):
        count = (y == i).sum()
        print(f"  {name}: {count} ({count/len(y)*100:.1f}%)")

    # Class weights for imbalanced data
    class_counts = np.bincount(y, minlength=5).astype(np.float32)
    class_weights = 1.0 / np.maximum(class_counts, 1)
    class_weights = class_weights / class_weights.sum() * 5
    print(f"Class weights: {class_weights}")

    # GroupKFold
    gkf = GroupKFold(n_splits=n_splits)
    best_model_state = None
    best_val_loss = float('inf')
    fold_metrics = []

    for fold_idx, (train_idx, val_idx) in enumerate(gkf.split(df, y, groups=groups)):
        print(f"\n--- Fold {fold_idx + 1}/{n_splits} ---")

        train_ds = DFIDataset(df.iloc[train_idx])
        val_ds = DFIDataset(df.iloc[val_idx])
        train_dl = DataLoader(train_ds, batch_size=batch_size, shuffle=True, num_workers=4)
        val_dl = DataLoader(val_ds, batch_size=batch_size, shuffle=False, num_workers=4)

        model = DFI_CNN().to(device)
        criterion = nn.CrossEntropyLoss(
            weight=torch.tensor(class_weights, dtype=torch.float32).to(device),
            reduction='none'
        )
        optimizer = torch.optim.Adam(model.parameters(), lr=lr)
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=5, factor=0.5)

        best_fold_loss = float('inf')
        patience_counter = 0

        for epoch in range(epochs):
            # Train
            model.train()
            train_loss = 0
            for batch in train_dl:
                size, flag, iat, rtt, ent, static, labels, weights = [b.to(device) for b in batch]
                logits = model(size, flag, iat, rtt, ent, static)
                loss_per_sample = criterion(logits, labels)
                loss = (loss_per_sample * weights).mean()

                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
                train_loss += loss.item()

            train_loss /= len(train_dl)

            # Validate
            model.eval()
            val_loss = 0
            all_preds = []
            all_labels = []
            with torch.no_grad():
                for batch in val_dl:
                    size, flag, iat, rtt, ent, static, labels, weights = [b.to(device) for b in batch]
                    logits = model(size, flag, iat, rtt, ent, static)
                    loss_per_sample = criterion(logits, labels)
                    loss = (loss_per_sample * weights).mean()
                    val_loss += loss.item()
                    all_preds.extend(logits.argmax(dim=1).cpu().numpy())
                    all_labels.extend(labels.cpu().numpy())

            val_loss /= len(val_dl)
            scheduler.step(val_loss)

            if epoch % 10 == 0 or epoch == epochs - 1:
                print(f"  Epoch {epoch+1}/{epochs}: train_loss={train_loss:.4f}, val_loss={val_loss:.4f}")

            if val_loss < best_fold_loss:
                best_fold_loss = val_loss
                patience_counter = 0
                if val_loss < best_val_loss:
                    best_val_loss = val_loss
                    best_model_state = model.state_dict().copy()
            else:
                patience_counter += 1
                if patience_counter >= 10:
                    print(f"  Early stopping at epoch {epoch+1}")
                    break

        # Fold metrics
        print(f"\nFold {fold_idx + 1} validation:")
        print(classification_report(all_labels, all_preds, target_names=LABEL_NAMES, zero_division=0))

        fold_metrics.append({
            'fold': fold_idx + 1,
            'val_loss': best_fold_loss,
            'report': classification_report(all_labels, all_preds, target_names=LABEL_NAMES,
                                            output_dict=True, zero_division=0),
        })

    # Save best model
    os.makedirs(output_dir, exist_ok=True)
    timestamp = time.strftime('%Y%m%d_%H%M%S')

    model_path = os.path.join(output_dir, f'cnn_{timestamp}.pt')
    torch.save(best_model_state, model_path)
    print(f"\nModel saved: {model_path}")

    metrics_path = os.path.join(output_dir, f'cnn_{timestamp}_metrics.json')
    with open(metrics_path, 'w') as f:
        json.dump({
            'model': 'cnn_v1',
            'timestamp': timestamp,
            'n_samples': len(df),
            'epochs': epochs,
            'batch_size': batch_size,
            'lr': lr,
            'folds': fold_metrics,
            'class_weights': class_weights.tolist(),
        }, f, indent=2, default=str)
    print(f"Metrics saved: {metrics_path}")

    return model_path


def main():
    parser = argparse.ArgumentParser(description='Train DFI CNN on packet sequences')
    parser.add_argument('csv', help='Path to CNN CSV export')
    parser.add_argument('--epochs', type=int, default=50)
    parser.add_argument('--batch-size', type=int, default=512)
    parser.add_argument('--lr', type=float, default=1e-3)
    parser.add_argument('--folds', type=int, default=5)
    parser.add_argument('--output', '-o', default=OUTPUT_DIR)
    args = parser.parse_args()

    train_cnn(args.csv, args.epochs, args.batch_size, args.lr, args.folds, args.output)


if __name__ == '__main__':
    main()
```

---

## Step 4: score.py — Model Predictions → ClickHouse

```python
#!/usr/bin/env python3
"""score.py — Score unscored flows with trained models, write predictions to CH.

Usage:
    python score.py xgb models/xgb_20260224.json
    python score.py cnn models/cnn_20260224.pt
    python score.py xgb models/xgb_20260224.json --hours 24  # Last 24h only
"""

import argparse
import os
import time

import numpy as np
from clickhouse_driver import Client

CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))
BATCH_SIZE = 10000
SEQ_LEN = 128
LABEL_NAMES = ['RECON', 'KNOCK', 'BRUTEFORCE', 'EXPLOIT', 'COMPROMISE']

STATIC_COLS = [
    'dst_port', 'ip_proto', 'app_proto',
    'pkts_fwd', 'pkts_rev', 'bytes_fwd', 'bytes_rev',
    'bytes_per_pkt_fwd', 'bytes_per_pkt_rev', 'pkt_ratio', 'byte_ratio',
    'rtt_ms', 'n_events',
    'entropy_first', 'entropy_fwd_mean', 'entropy_rev_mean',
    'printable_frac', 'null_frac', 'byte_std', 'high_entropy_frac', 'payload_len_first',
    'ja3_freq', 'tls_version', 'tls_cipher_count', 'tls_ext_count', 'tls_has_sni',
    'hassh_freq', 'ssh_kex_count',
    'http_method', 'http_uri_len', 'http_header_count', 'http_ua_freq',
    'http_has_body', 'http_status',
    'dns_qtype', 'dns_qname_len',
    'src_flow_count', 'src_unique_ports', 'src_unique_protos',
    'src_unique_dsts', 'src_span_min', 'src_avg_pps',
]


def score_xgb(ch: Client, model_path: str, model_version: str, hours: int = 0):
    """Score unscored flows with XGBoost model."""
    import xgboost as xgb

    model = xgb.Booster()
    model.load_model(model_path)
    print(f"Loaded XGBoost model: {model_path}")

    # Find unscored flows
    where = ""
    if hours > 0:
        where = f"AND first_ts >= now() - INTERVAL {hours} HOUR"

    unscored_sql = f"""
        SELECT * FROM dfi.v_xgb
        WHERE flow_id NOT IN (
            SELECT flow_id FROM dfi.model_predictions
            WHERE model_name = 'xgb_v1' AND model_version = '{model_version}'
        )
        {where}
        LIMIT {BATCH_SIZE}
    """

    meta = ch.execute("SELECT * FROM dfi.v_xgb LIMIT 0", with_column_types=True)
    col_names = [c[0] for c in meta[1]]
    feat_cols = [c for c in col_names if c not in
                 ['flow_id', 'session_key', 'actor_id', 'label',
                  'label_confidence', 'evidence_mask', 'evidence_detail']]

    total_scored = 0

    while True:
        rows = ch.execute(unscored_sql)
        if not rows:
            break

        import pandas as pd
        df = pd.DataFrame(rows, columns=col_names)

        X = df[feat_cols].values.astype(np.float32)
        dmat = xgb.DMatrix(X, feature_names=feat_cols)
        probs = model.predict(dmat)
        preds = np.argmax(probs, axis=1)
        confs = np.max(probs, axis=1)

        # Write predictions to CH
        pred_rows = []
        for idx in range(len(df)):
            pred_rows.append({
                'flow_id': df.iloc[idx]['flow_id'],
                'src_ip': df.iloc[idx]['src_ip'] if 'src_ip' in df.columns else '0.0.0.0',
                'dst_ip': df.iloc[idx]['dst_ip'] if 'dst_ip' in df.columns else '0.0.0.0',
                'dst_port': int(df.iloc[idx]['dst_port']),
                'flow_first_ts': df.iloc[idx].get('first_ts', None),
                'model_name': 'xgb_v1',
                'model_version': model_version,
                'label': int(preds[idx]),
                'confidence': float(confs[idx]),
                'class_probs': probs[idx].tolist(),
            })

        ch.execute("INSERT INTO dfi.model_predictions_buffer VALUES", pred_rows)
        total_scored += len(pred_rows)
        print(f"  Scored {len(pred_rows)} flows (total: {total_scored})")

    print(f"XGBoost scoring complete: {total_scored} flows scored")
    return total_scored


def score_cnn(ch: Client, model_path: str, model_version: str, hours: int = 0):
    """Score unscored flows with CNN model."""
    import torch
    from train_cnn import DFI_CNN  # Import model class

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model = DFI_CNN()
    model.load_state_dict(torch.load(model_path, map_location=device))
    model.to(device)
    model.eval()
    print(f"Loaded CNN model: {model_path} (device: {device})")

    # Find unscored flows with sequences
    where = ""
    if hours > 0:
        where = f"AND f.first_ts >= now() - INTERVAL {hours} HOUR"

    total_scored = 0

    # Get flows that have packets (D2+) and no CNN prediction yet
    flow_ids = ch.execute(f"""
        SELECT DISTINCT f.flow_id
        FROM dfi.flows f
        INNER JOIN dfi.packets p ON p.flow_id = f.flow_id
        WHERE f.flow_id NOT IN (
            SELECT flow_id FROM dfi.model_predictions
            WHERE model_name = 'cnn_v1' AND model_version = '{model_version}'
        )
        {where}
        LIMIT {BATCH_SIZE}
    """)

    if not flow_ids:
        print("No unscored flows with sequences found")
        return 0

    fids = [r[0] for r in flow_ids]

    # Fetch sequence data
    seq_data = ch.execute("""
        SELECT flow_id,
               groupArray(128)(size_dir_token) AS size_arr,
               groupArray(128)(flag_token) AS flag_arr,
               groupArray(128)(iat_log_ms_bin) AS iat_arr,
               groupArray(128)(iat_rtt_bin) AS rtt_arr,
               groupArray(128)(entropy_bin) AS ent_arr
        FROM (SELECT * FROM dfi.packets WHERE flow_id IN %(fids)s ORDER BY flow_id, seq_idx)
        GROUP BY flow_id
    """, {'fids': fids})

    # Fetch static features from v_xgb
    static_data = ch.execute("""
        SELECT * FROM dfi.v_xgb WHERE flow_id IN %(fids)s
    """, {'fids': fids})
    meta = ch.execute("SELECT * FROM dfi.v_xgb LIMIT 0", with_column_types=True)
    xgb_col_names = [c[0] for c in meta[1]]

    # Build lookup dicts
    seq_map = {}
    for row in seq_data:
        fid = row[0]
        def pad(arr): return (list(arr) + [0] * SEQ_LEN)[:SEQ_LEN]
        seq_map[fid] = {
            'size': np.array(pad(row[1])) + 11,  # offset for embedding
            'flag': np.array(pad(row[2])),
            'iat': np.array(pad(row[3])),
            'rtt': np.array(pad(row[4])),
            'ent': np.array(pad(row[5])),
        }

    static_map = {}
    for row in static_data:
        rd = dict(zip(xgb_col_names, row))
        static_map[rd['flow_id']] = rd

    # Score in batches
    pred_rows = []
    for fid in fids:
        if fid not in seq_map or fid not in static_map:
            continue

        s = seq_map[fid]
        st = static_map[fid]
        static_vals = np.array([float(st.get(c, 0) or 0) for c in STATIC_COLS], dtype=np.float32)

        with torch.no_grad():
            size_t = torch.tensor(s['size'], dtype=torch.long).unsqueeze(0).to(device)
            flag_t = torch.tensor(s['flag'], dtype=torch.long).unsqueeze(0).to(device)
            iat_t = torch.tensor(s['iat'], dtype=torch.long).unsqueeze(0).to(device)
            rtt_t = torch.tensor(s['rtt'], dtype=torch.long).unsqueeze(0).to(device)
            ent_t = torch.tensor(s['ent'], dtype=torch.long).unsqueeze(0).to(device)
            static_t = torch.tensor(static_vals, dtype=torch.float32).unsqueeze(0).to(device)

            logits = model(size_t, flag_t, iat_t, rtt_t, ent_t, static_t)
            probs = torch.softmax(logits, dim=1).cpu().numpy()[0]

        pred = int(np.argmax(probs))
        conf = float(np.max(probs))

        pred_rows.append({
            'flow_id': fid,
            'src_ip': st.get('src_ip', '0.0.0.0'),
            'dst_ip': st.get('dst_ip', '0.0.0.0'),
            'dst_port': int(st.get('dst_port', 0)),
            'flow_first_ts': st.get('first_ts', None),
            'model_name': 'cnn_v1',
            'model_version': model_version,
            'label': pred,
            'confidence': conf,
            'class_probs': probs.tolist(),
        })

    if pred_rows:
        ch.execute("INSERT INTO dfi.model_predictions_buffer VALUES", pred_rows)
        total_scored = len(pred_rows)
        print(f"CNN scoring complete: {total_scored} flows scored")
    else:
        total_scored = 0
        print("No flows to score")

    return total_scored


def main():
    parser = argparse.ArgumentParser(description='Score flows with trained models')
    parser.add_argument('model_type', choices=['xgb', 'cnn'], help='Model type')
    parser.add_argument('model_path', help='Path to trained model file')
    parser.add_argument('--version', default='v1', help='Model version tag')
    parser.add_argument('--hours', type=int, default=0, help='Only score last N hours')
    args = parser.parse_args()

    ch = Client(CH_HOST, port=CH_PORT)

    if args.model_type == 'xgb':
        score_xgb(ch, args.model_path, args.version, args.hours)
    else:
        score_cnn(ch, args.model_path, args.version, args.hours)


if __name__ == '__main__':
    main()
```

---

## Verification

1. **Export produces valid CSVs:**
   ```bash
   python3 /opt/dfi2/ml/export.py xgb -o /tmp/test_xgb.csv
   head -1 /tmp/test_xgb.csv | tr ',' '\n' | wc -l
   # Should be 82 columns

   python3 /opt/dfi2/ml/export.py cnn -o /tmp/test_cnn.csv
   head -1 /tmp/test_cnn.csv | tr ',' '\n' | wc -l
   # Should be 689 columns
   ```

2. **Balanced export:**
   ```bash
   python3 /opt/dfi2/ml/export.py xgb --balanced 100 -o /tmp/test_balanced.csv
   # Should print ~100 per class (or fewer if not enough data)
   ```

3. **XGBoost trains:**
   ```bash
   python3 /opt/dfi2/ml/train_xgb.py /tmp/test_xgb.csv
   # Should complete without errors, print confusion matrix
   ls /opt/dfi2/ml/models/xgb_*.json
   ```

4. **CNN trains:**
   ```bash
   python3 /opt/dfi2/ml/train_cnn.py /tmp/test_cnn.csv --epochs 5
   # Should show decreasing loss
   ls /opt/dfi2/ml/models/cnn_*.pt
   ```

5. **Scoring works:**
   ```bash
   python3 /opt/dfi2/ml/score.py xgb /opt/dfi2/ml/models/xgb_*.json --hours 24
   clickhouse-client --query "
       SELECT model_name, count() as predictions
       FROM dfi.model_predictions
       GROUP BY model_name
   "
   ```

6. **Predictions in CH:**
   ```bash
   clickhouse-client --query "
       SELECT model_name, label, count() as cnt,
              avg(confidence) as avg_conf
       FROM dfi.model_predictions
       GROUP BY model_name, label
       ORDER BY model_name, label
   "
   ```

---

## Acceptance Criteria

- [ ] `export.py xgb` produces valid 82-column CSV
- [ ] `export.py cnn` produces valid 689-column CSV
- [ ] Balanced export works (N per class)
- [ ] High-confidence filtering works (--min-conf)
- [ ] XGBoost trains with GroupKFold, no data leakage
- [ ] XGBoost confusion matrix shows reasonable results (not random)
- [ ] CNN trains, loss decreases across epochs
- [ ] CNN inception-style multi-kernel architecture works
- [ ] Class-weighted loss handles imbalanced data
- [ ] Confidence weighting (label_confidence) applied in both models
- [ ] Models saved to disk (JSON for XGBoost, .pt for CNN)
- [ ] Metrics saved (fold results, feature importance for XGBoost)
- [ ] `score.py xgb` writes predictions to `dfi.model_predictions`
- [ ] `score.py cnn` writes predictions to `dfi.model_predictions`
- [ ] Predictions include class_probs array (5 probabilities)
- [ ] Dependencies installed: `xgboost`, `torch`, `scikit-learn`, `pandas`, `clickhouse-driver`

## Important Notes

- **GroupKFold by actor_id is non-negotiable.** Without it, the same attacker tool appears in both train and test, inflating metrics. The `actor_id` field is a fingerprint-based cluster ID that groups flows from the same tool/infrastructure.
- **CNN only scores D2+ flows.** Flows at D1 have no packets table entries and cannot be fed to the CNN. XGBoost can score all flows (D1+) since it uses scalar features only.
- **Scoring is separate from training.** The `score.py` script runs independently (manually or via cron). It reads the latest model, finds unscored flows, and writes predictions. Multiple model versions can coexist in the `model_predictions` table.
- **CNN batch scoring is slow per-flow.** The current implementation scores one flow at a time. For production, batch the sequences into tensors (e.g., 128 flows per batch) for GPU-friendly inference. The per-flow approach works for initial validation.
- **Install PyTorch with CUDA if GPU available:** `pip install torch --index-url https://download.pytorch.org/whl/cu121`. PV1 may not have a GPU — CPU training is fine for initial models.
