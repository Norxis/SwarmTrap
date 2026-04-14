#!/usr/bin/env python3
"""Per-service CNN training from D2 capture data.

Copied from proven train_cnn_3class.py. Binary: ATTACK(0) vs CLEAN(1).
Input: parquet from prep_d2_cnn.py (pre-expanded arrays, NO PORT FEATURES).

CRITICAL: CNN learns from packet sequences + behavioral stats ONLY.
dst_port, ip_proto, app_proto, service_id are EXCLUDED by prep_d2_cnn.py.

Usage:
    python3 train_d2_cnn.py training_cnn_remote_access.parquet --epochs 50 --folds 5 -o models/cnn_ra_v1
"""
import argparse
import json
import os
import time

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GroupKFold

OUTPUT_DIR = os.environ.get('ML_OUTPUT_DIR', '/nvme0n1-disk/ml/models')
SEQ_LEN = 128
NUM_CLASSES = 2
CLASS_NAMES = ['ATTACK', 'CLEAN']

# Static features — NO PORT, NO PROTO (must match prep_d2_cnn.py CNN_STATIC_COLS)
CNN_STATIC_COLS = [
    'pkts_fwd', 'pkts_rev', 'bytes_fwd', 'bytes_rev',
    'bytes_per_pkt_fwd', 'bytes_per_pkt_rev', 'pkt_ratio', 'byte_ratio',
    'duration_ms', 'rtt_ms', 'pps', 'bps',
    'iat_fwd_mean_ms', 'iat_fwd_std_ms',
    'think_time_mean_ms', 'think_time_std_ms',
    'iat_to_rtt', 'payload_rtt_ratio',
    'entropy_first', 'entropy_fwd_mean', 'entropy_rev_mean',
    'printable_frac', 'null_frac', 'byte_std', 'high_entropy_frac',
    'payload_len_first',
    'fwd_size_mean', 'fwd_size_std', 'fwd_size_min', 'fwd_size_max',
    'rev_size_mean', 'rev_size_std', 'rev_size_max',
    'hist_tiny', 'hist_small', 'hist_medium', 'hist_large', 'hist_full', 'frac_full',
    'syn_count', 'fin_count', 'rst_count', 'psh_count', 'ack_only_count',
    'conn_state', 'rst_frac', 'syn_to_data', 'psh_burst_max',
    'retransmit_est', 'window_size_init',
    'src_flow_count', 'src_unique_ports', 'src_unique_protos',
    'src_unique_dsts', 'src_span_min', 'src_avg_pps',
    'n_events',
]


class DFI_CNN(nn.Module):
    def __init__(self, num_classes=2, n_static=50):
        super().__init__()
        self.size_emb = nn.Embedding(24, 12, padding_idx=0)
        self.flag_emb = nn.Embedding(33, 6, padding_idx=0)
        self.iat_emb = nn.Embedding(9, 6, padding_idx=0)
        self.rtt_emb = nn.Embedding(10, 6, padding_idx=0)
        self.ent_emb = nn.Embedding(7, 4, padding_idx=0)
        # Total per position: 12+6+6+6+4 = 34

        self.conv3 = nn.Sequential(nn.Conv1d(34, 32, 3, padding=1), nn.BatchNorm1d(32), nn.ReLU())
        self.conv5 = nn.Sequential(nn.Conv1d(34, 32, 5, padding=2), nn.BatchNorm1d(32), nn.ReLU())
        self.conv7 = nn.Sequential(nn.Conv1d(34, 32, 7, padding=3), nn.BatchNorm1d(32), nn.ReLU())
        self.merge = nn.Sequential(nn.Conv1d(96, 128, 5, padding=2), nn.BatchNorm1d(128), nn.ReLU(), nn.AdaptiveMaxPool1d(1))

        self.static_bn = nn.BatchNorm1d(n_static)
        self.head = nn.Sequential(
            nn.Linear(128 + n_static, 128), nn.ReLU(), nn.Dropout(0.3),
            nn.Linear(128, num_classes),
        )

    def forward(self, size_seq, flag_seq, iat_seq, rtt_seq, ent_seq, static_feat):
        s = self.size_emb(size_seq)
        f = self.flag_emb(flag_seq)
        i = self.iat_emb(iat_seq)
        r = self.rtt_emb(rtt_seq)
        e = self.ent_emb(ent_seq)
        x = torch.cat([s, f, i, r, e], dim=2).transpose(1, 2)
        mask = (size_seq != 0).unsqueeze(1).float()
        x = x * mask
        x = torch.cat([self.conv3(x), self.conv5(x), self.conv7(x)], dim=1)
        x = self.merge(x).squeeze(2)
        m = self.static_bn(static_feat)
        return self.head(torch.cat([x, m], dim=1))


def train_epoch(model, crit, opt, scaler, use_amp, size, flag, iat, rtt, ent, static, labels, weights, batch_size, device):
    model.train()
    n = len(labels)
    perm = torch.randperm(n)
    total_loss = 0.0
    n_batches = 0
    for i in range(0, n, batch_size):
        idx = perm[i:i+batch_size]
        b_size = size[idx].to(device, non_blocking=True)
        b_flag = flag[idx].to(device, non_blocking=True)
        b_iat = iat[idx].to(device, non_blocking=True)
        b_rtt = rtt[idx].to(device, non_blocking=True)
        b_ent = ent[idx].to(device, non_blocking=True)
        b_static = static[idx].to(device, non_blocking=True)
        b_labels = labels[idx].to(device, non_blocking=True)
        b_weights = weights[idx].to(device, non_blocking=True)
        with torch.amp.autocast('cuda', enabled=use_amp):
            logits = model(b_size, b_flag, b_iat, b_rtt, b_ent, b_static)
            loss = (crit(logits, b_labels) * b_weights).mean()
        opt.zero_grad()
        scaler.scale(loss).backward()
        scaler.step(opt)
        scaler.update()
        total_loss += loss.item()
        n_batches += 1
    return total_loss / max(n_batches, 1)


def eval_epoch(model, crit, use_amp, size, flag, iat, rtt, ent, static, labels, weights, batch_size, device):
    model.eval()
    n = len(labels)
    total_loss = 0.0
    n_batches = 0
    all_labels = []
    all_preds = []
    with torch.no_grad():
        for i in range(0, n, batch_size):
            end = min(i + batch_size, n)
            b_size = size[i:end].to(device, non_blocking=True)
            b_flag = flag[i:end].to(device, non_blocking=True)
            b_iat = iat[i:end].to(device, non_blocking=True)
            b_rtt = rtt[i:end].to(device, non_blocking=True)
            b_ent = ent[i:end].to(device, non_blocking=True)
            b_static = static[i:end].to(device, non_blocking=True)
            b_labels = labels[i:end].to(device, non_blocking=True)
            b_weights = weights[i:end].to(device, non_blocking=True)
            with torch.amp.autocast('cuda', enabled=use_amp):
                logits = model(b_size, b_flag, b_iat, b_rtt, b_ent, b_static)
                loss = (crit(logits, b_labels) * b_weights).mean()
            total_loss += loss.item()
            n_batches += 1
            all_labels.append(b_labels.cpu())
            all_preds.append(logits.argmax(dim=1).cpu())
    all_labels = torch.cat(all_labels).numpy()
    all_preds = torch.cat(all_preds).numpy()
    return total_loss / max(n_batches, 1), all_labels, all_preds


def main():
    ap = argparse.ArgumentParser(description='Per-service CNN: ATTACK vs CLEAN (NO PORT FEATURES)')
    ap.add_argument('data', help='Parquet from prep_d2_cnn.py')
    ap.add_argument('--epochs', type=int, default=50)
    ap.add_argument('--batch-size', type=int, default=16384)
    ap.add_argument('--lr', type=float, default=0.004)
    ap.add_argument('--folds', type=int, default=5)
    ap.add_argument('-o', '--output', default=OUTPUT_DIR)
    args = ap.parse_args()

    start = time.time()
    os.makedirs(args.output, exist_ok=True)

    try:
        torch.set_num_interop_threads(4)
    except RuntimeError:
        pass
    torch.set_num_threads(72)
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    if device.type == 'cuda':
        torch.backends.cudnn.benchmark = True
        torch.backends.cuda.matmul.allow_tf32 = True
        torch.backends.cudnn.allow_tf32 = True
    use_amp = device.type == 'cuda'
    scaler = torch.amp.GradScaler('cuda', enabled=use_amp)
    print(f'Device: {device}, AMP: {use_amp}', flush=True)

    # Load
    print(f'Loading {args.data}...', flush=True)
    t0 = time.time()
    df = pd.read_parquet(args.data)
    df = df.loc[:, ~df.columns.duplicated()]
    print(f'Loaded {len(df):,} rows, {len(df.columns)} cols ({time.time()-t0:.1f}s)', flush=True)

    # Verify NO PORT FEATURES
    bad = [c for c in ('dst_port', 'ip_proto', 'app_proto', 'service_id') if c in df.columns]
    if bad:
        print(f'CRITICAL: Removing port features that should not be here: {bad}')
        df = df.drop(columns=bad)

    # Labels
    y = df['label'].values.astype(np.int64)
    print(f'Classes: { {CLASS_NAMES[i]: int((y==i).sum()) for i in range(NUM_CLASSES)} }', flush=True)

    # Load pre-expanded array columns
    print('Loading CNN arrays...', flush=True)
    t0 = time.time()
    size_cols = [f'size_dir_seq_{i}' for i in range(1, SEQ_LEN + 1)]
    flag_cols = [f'tcp_flags_seq_{i}' for i in range(1, SEQ_LEN + 1)]
    iat_cols = [f'iat_log_ms_seq_{i}' for i in range(1, SEQ_LEN + 1)]
    rtt_cols = [f'iat_rtt_bin_seq_{i}' for i in range(1, SEQ_LEN + 1)]
    ent_cols = [f'entropy_bin_seq_{i}' for i in range(1, SEQ_LEN + 1)]

    np_size = df[size_cols].fillna(0).values.astype(np.int64)
    np_size = np.where(np_size == 0, 0, np_size + 12).astype(np.int64)  # offset [-11..+11] → [1..23]
    np_flag = df[flag_cols].fillna(0).values.astype(np.int64)
    np_iat = df[iat_cols].fillna(0).values.astype(np.int64)
    np_rtt = df[rtt_cols].fillna(0).values.astype(np.int64)
    np_ent = df[ent_cols].fillna(0).values.astype(np.int64)
    print(f'  Arrays loaded in {time.time()-t0:.1f}s', flush=True)

    # Static features — NO PORT (must match prep_d2_cnn.py)
    avail_static = [c for c in CNN_STATIC_COLS if c in df.columns]
    for c in avail_static:
        if df[c].dtype == object:
            df[c] = pd.to_numeric(df[c], errors='coerce')
    np_static = df[avail_static].fillna(0).values.astype(np.float32)
    n_static = len(avail_static)
    print(f'Static features: {n_static} (NO PORT — port-independent model)', flush=True)

    np_weights = np.ones(len(y), dtype=np.float32)

    # Groups for GroupKFold — by src_ip
    if 'src_ip' in df.columns:
        groups = df['src_ip'].fillna('unknown').values
    else:
        groups = np.arange(len(df)).astype(str)

    del df
    print(f'Data ready, {len(y):,} samples', flush=True)

    # Pinned CPU tensors
    t0 = time.time()
    g_size = torch.tensor(np_size, dtype=torch.long).pin_memory()
    g_flag = torch.tensor(np_flag, dtype=torch.long).pin_memory()
    g_iat = torch.tensor(np_iat, dtype=torch.long).pin_memory()
    g_rtt = torch.tensor(np_rtt, dtype=torch.long).pin_memory()
    g_ent = torch.tensor(np_ent, dtype=torch.long).pin_memory()
    g_static = torch.tensor(np_static, dtype=torch.float32).pin_memory()
    g_labels = torch.tensor(y, dtype=torch.long).pin_memory()
    g_weights = torch.tensor(np_weights, dtype=torch.float32).pin_memory()
    del np_size, np_flag, np_iat, np_rtt, np_ent, np_static, np_weights
    print(f'Pinned tensors ready ({time.time()-t0:.1f}s)', flush=True)

    # Class weights — balanced
    class_counts = np.bincount(y, minlength=NUM_CLASSES).astype(np.float32)
    class_weights = 1.0 / np.maximum(class_counts, 1)
    class_weights = class_weights / class_weights.sum() * NUM_CLASSES
    print(f'Class weights: {class_weights.tolist()}', flush=True)

    # Cross-validation
    gkf = GroupKFold(n_splits=args.folds)
    best_state, best_loss, best_epoch_count = None, float('inf'), 0
    fold_metrics = []

    for fi, (tr, va) in enumerate(gkf.split(np.zeros(len(y)), y, groups=groups), start=1):
        print(f'\n=== Fold {fi}/{args.folds} ({len(tr):,} train, {len(va):,} val) ===', flush=True)
        t_fold = time.time()

        tr_size, tr_flag, tr_iat, tr_rtt, tr_ent = g_size[tr], g_flag[tr], g_iat[tr], g_rtt[tr], g_ent[tr]
        tr_static, tr_labels, tr_weights = g_static[tr], g_labels[tr], g_weights[tr]
        va_size, va_flag, va_iat, va_rtt, va_ent = g_size[va], g_flag[va], g_iat[va], g_rtt[va], g_ent[va]
        va_static, va_labels, va_weights = g_static[va], g_labels[va], g_weights[va]

        model = DFI_CNN(num_classes=NUM_CLASSES, n_static=n_static).to(device)
        crit = nn.CrossEntropyLoss(weight=torch.tensor(class_weights, dtype=torch.float32).to(device), reduction='none')
        opt = torch.optim.Adam(model.parameters(), lr=args.lr)
        sch = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, patience=5, factor=0.5)

        best_fold, patience_count = float('inf'), 0

        for epoch in range(args.epochs):
            train_loss = train_epoch(model, crit, opt, scaler, use_amp,
                                     tr_size, tr_flag, tr_iat, tr_rtt, tr_ent, tr_static, tr_labels, tr_weights,
                                     args.batch_size, device)
            val_loss, val_labels, val_preds = eval_epoch(model, crit, use_amp,
                                                          va_size, va_flag, va_iat, va_rtt, va_ent, va_static, va_labels, va_weights,
                                                          args.batch_size, device)
            sch.step(val_loss)

            if val_loss < best_fold:
                best_fold = val_loss
                patience_count = 0
                if val_loss < best_loss:
                    best_loss = val_loss
                    best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
                    best_epoch_count = epoch + 1
            else:
                patience_count += 1
                if patience_count >= 10:
                    print(f'  Epoch {epoch+1}: early stop, val_loss={val_loss:.6f}', flush=True)
                    break

            if (epoch + 1) % 5 == 0:
                print(f'  Epoch {epoch+1}: train={train_loss:.6f} val={val_loss:.6f}', flush=True)

        rep = classification_report(val_labels, val_preds, labels=list(range(NUM_CLASSES)),
                                    target_names=CLASS_NAMES, output_dict=True, zero_division=0)
        cm = confusion_matrix(val_labels, val_preds).tolist()
        fold_metrics.append({
            'fold': fi, 'val_loss': best_fold, 'accuracy': rep['accuracy'],
            'macro_f1': rep['macro avg']['f1-score'], 'confusion_matrix': cm,
        })
        print(f'  Fold {fi}: val_loss={best_fold:.6f}  acc={rep["accuracy"]:.4f}  '
              f'macro_f1={rep["macro avg"]["f1-score"]:.4f}  ({time.time()-t_fold:.0f}s)', flush=True)
        print(classification_report(val_labels, val_preds, target_names=CLASS_NAMES, digits=4), flush=True)

        del tr_size, tr_flag, tr_iat, tr_rtt, tr_ent, tr_static, tr_labels, tr_weights
        del va_size, va_flag, va_iat, va_rtt, va_ent, va_static, va_labels, va_weights

    # Retrain on all data
    print(f'\n=== Retraining on all data ({len(y):,}, {best_epoch_count} epochs) ===', flush=True)
    t_full = time.time()
    final_model = DFI_CNN(num_classes=NUM_CLASSES, n_static=n_static).to(device)
    final_crit = nn.CrossEntropyLoss(weight=torch.tensor(class_weights, dtype=torch.float32).to(device), reduction='none')
    final_opt = torch.optim.Adam(final_model.parameters(), lr=args.lr)
    final_scaler = torch.amp.GradScaler('cuda', enabled=use_amp)
    for ep in range(best_epoch_count):
        train_epoch(final_model, final_crit, final_opt, final_scaler, use_amp,
                    g_size, g_flag, g_iat, g_rtt, g_ent, g_static, g_labels, g_weights,
                    args.batch_size, device)
        if (ep + 1) % 5 == 0:
            print(f'  Full retrain epoch {ep+1}/{best_epoch_count}', flush=True)
    best_state = {k: v.detach().cpu().clone() for k, v in final_model.state_dict().items()}
    print(f'  Retrain done ({time.time()-t_full:.0f}s)', flush=True)

    # Save
    ts = time.strftime('%Y%m%d_%H%M%S')
    model_path = os.path.join(args.output, f'cnn_d2_{ts}.pt')
    metrics_path = os.path.join(args.output, f'cnn_d2_{ts}_metrics.json')
    torch.save(best_state, model_path)
    with open(metrics_path, 'w') as f:
        json.dump({
            'model': 'cnn_d2_v1',
            'timestamp': ts,
            'classes': CLASS_NAMES,
            'n_samples': len(y),
            'n_static': n_static,
            'static_cols': avail_static,
            'port_features': 'EXCLUDED — port-independent model',
            'epochs': args.epochs,
            'best_epoch_count': best_epoch_count,
            'batch_size': args.batch_size,
            'lr': args.lr,
            'class_weights': class_weights.tolist(),
            'folds': fold_metrics,
        }, f, indent=2)

    elapsed = time.time() - start
    print(f'\nSaved: {model_path}')
    print(f'Total: {elapsed:.0f}s ({elapsed/60:.1f}min)', flush=True)


if __name__ == '__main__':
    main()
