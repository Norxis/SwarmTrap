#!/usr/bin/env python3
# Updated for combined 722-col dataset (XGB+CNN in one row)
"""CNN training for DFI v2. Manual batching with torch.randperm — no DataLoader.
Pre-extracts all data to GPU tensors. MAX CPU + MAX GPU everywhere."""
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

OUTPUT_DIR = os.environ.get('ML_OUTPUT_DIR', '/opt/dfi2/ml/models')
SEQ_LEN = 128

# 42 static features for CNN static branch — src_* are REAL values from combined dataset,
# no zero-fill. Matches CNN_STATIC_COLS in export.py.
CNN_STATIC_COLS = [
    'dst_port', 'ip_proto', 'app_proto', 'pkts_fwd', 'pkts_rev', 'bytes_fwd', 'bytes_rev',
    'bytes_per_pkt_fwd', 'bytes_per_pkt_rev', 'pkt_ratio', 'byte_ratio', 'rtt_ms', 'n_events',
    'entropy_first', 'entropy_fwd_mean', 'entropy_rev_mean', 'printable_frac', 'null_frac',
    'byte_std', 'high_entropy_frac', 'payload_len_first', 'ja3_freq', 'tls_version',
    'tls_cipher_count', 'tls_ext_count', 'tls_has_sni', 'hassh_freq', 'ssh_kex_count',
    'http_method', 'http_uri_len', 'http_header_count', 'http_ua_freq', 'http_has_body',
    'http_status', 'dns_qtype', 'dns_qname_len', 'src_flow_count', 'src_unique_ports',
    'src_unique_protos', 'src_unique_dsts', 'src_span_min', 'src_avg_pps',
]
# Backwards-compatibility alias
STATIC_COLS = CNN_STATIC_COLS


class DFI_CNN(nn.Module):
    def __init__(self, num_classes=2):
        super().__init__()
        self.size_emb = nn.Embedding(24, 12, padding_idx=0)
        self.flag_emb = nn.Embedding(17, 6, padding_idx=0)
        self.iat_emb = nn.Embedding(9, 6, padding_idx=0)
        self.rtt_emb = nn.Embedding(10, 6, padding_idx=0)
        self.ent_emb = nn.Embedding(7, 4, padding_idx=0)

        self.conv3 = nn.Sequential(nn.Conv1d(34, 32, 3, padding=1), nn.BatchNorm1d(32), nn.ReLU())
        self.conv5 = nn.Sequential(nn.Conv1d(34, 32, 5, padding=2), nn.BatchNorm1d(32), nn.ReLU())
        self.conv7 = nn.Sequential(nn.Conv1d(34, 32, 7, padding=3), nn.BatchNorm1d(32), nn.ReLU())
        self.merge = nn.Sequential(nn.Conv1d(96, 128, 5, padding=2), nn.BatchNorm1d(128), nn.ReLU(), nn.AdaptiveMaxPool1d(1))

        self.static_bn = nn.BatchNorm1d(42)
        self.head = nn.Sequential(nn.Linear(170, 128), nn.ReLU(), nn.Dropout(0.3), nn.Linear(128, num_classes))

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
    """Train one epoch with manual batching. CPU pinned tensors, batch transfer to GPU."""
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
    """Evaluate one epoch. CPU pinned tensors, batch transfer to GPU."""
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


def train_cnn(csv_path: str, epochs: int = 50, batch_size: int = 512, lr: float = 1e-3,
              n_splits: int = 5, output_dir: str = OUTPUT_DIR,
              scale_pos_weight: float = 1.0, evil: bool = False):
    start = time.time()

    if evil:
        label_names = ['CLEAN', 'EVIL']
        model_prefix = 'cnn_evil'
        model_tag = 'cnn_evil_02'
    else:
        label_names = ['NORM', 'ATTACK']
        model_prefix = 'cnn'
        model_tag = 'cnn_v2_attack_vs_norm'

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
    print(f'  Device: {device}, threads: {torch.get_num_threads()}, AMP: {use_amp}', flush=True)

    # === Load data (combined 722-col parquet or legacy CSV) ===
    print(f'  Loading {csv_path}...', flush=True)
    t0 = time.time()
    if csv_path.endswith('.parquet'):
        df = pd.read_parquet(csv_path)
    else:
        df = pd.read_csv(csv_path, engine='pyarrow', na_values=[r'\N'])
    df.columns = [c.replace('f.', '') for c in df.columns]
    print(f'  Loaded {len(df):,} rows, {len(df.columns)} cols in {time.time()-t0:.1f}s', flush=True)

    for c in CNN_STATIC_COLS:
        if c in df.columns and df[c].dtype == object:
            df[c] = pd.to_numeric(df[c], errors='coerce')

    # === Labels ===
    y = df['label'].values.astype(np.int64)
    if 5 in y:
        y = np.where(y == 5, 0, 1).astype(np.int64)
    label_dist = {label_names[i]: int((y == i).sum()) for i in range(2)}
    print(f'  Labels: {label_dist}', flush=True)

    # === Extract ALL to numpy ONCE ===
    # Combined format uses: size_dir_seq_{i}, tcp_flags_seq_{i}, iat_log_ms_seq_{i},
    #                        iat_rtt_bin_seq_{i}, entropy_bin_seq_{i}
    # Legacy prep format used flag_token_seq / iat_log_ms_bin_seq — detect and handle both.
    t0 = time.time()
    if 'flag_token_seq_1' in df.columns:
        flag_prefix, iat_prefix = 'flag_token_seq', 'iat_log_ms_bin_seq'
        size_already_offset = True
    else:
        flag_prefix, iat_prefix = 'tcp_flags_seq', 'iat_log_ms_seq'
        size_already_offset = False

    size_cols = [f'size_dir_seq_{i}' for i in range(1, SEQ_LEN + 1)]
    flag_cols = [f'{flag_prefix}_{i}' for i in range(1, SEQ_LEN + 1)]
    iat_cols = [f'{iat_prefix}_{i}' for i in range(1, SEQ_LEN + 1)]
    rtt_cols = [f'iat_rtt_bin_seq_{i}' for i in range(1, SEQ_LEN + 1)]
    ent_cols = [f'entropy_bin_seq_{i}' for i in range(1, SEQ_LEN + 1)]

    raw_size = df[size_cols].fillna(0).values.astype(np.int64)
    if size_already_offset:
        np_size = raw_size
    else:
        np_size = np.where(raw_size == 0, 0, raw_size + 12).astype(np.int64)
    np_flag = df[flag_cols].fillna(0).values.astype(np.int64)
    np_iat = df[iat_cols].fillna(0).values.astype(np.int64)
    np_rtt = df[rtt_cols].fillna(0).values.astype(np.int64)
    np_ent = df[ent_cols].fillna(0).values.astype(np.int64)
    # src_* are real values from combined dataset — fillna(0) handles any missing only
    np_static = df[CNN_STATIC_COLS].fillna(0).values.astype(np.float32)
    np_weights = df['label_confidence'].fillna(0.5).values.astype(np.float32)

    # Groups
    rng = np.random.RandomState(42)
    if 'actor_id' in df.columns and df['actor_id'].fillna('').replace('', np.nan).dropna().nunique() >= n_splits:
        groups = df['actor_id'].fillna('').copy()
        empty_mask = groups == ''
        if empty_mask.any():
            groups.loc[empty_mask] = [f'rand_{rng.randint(0, 1000)}' for _ in range(empty_mask.sum())]
        norm_mask = groups == 'norm'
        if norm_mask.any():
            groups.loc[norm_mask] = [f'norm_{rng.randint(0, 1000)}' for _ in range(norm_mask.sum())]
        groups = groups.values
    else:
        groups = np.array([f'g_{rng.randint(0, 1000)}' for _ in range(len(df))])

    del df
    print(f'  Extracted numpy in {time.time()-t0:.1f}s', flush=True)

    # === Pinned CPU tensors for fast GPU transfer per batch ===
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
    print(f'  Pinned CPU tensors ready in {time.time()-t0:.1f}s', flush=True)

    # === Class weights ===
    if scale_pos_weight != 1.0:
        class_weights = np.array([1.0, scale_pos_weight], dtype=np.float32)
    else:
        class_counts = np.bincount(y, minlength=2).astype(np.float32)
        class_weights = 1.0 / np.maximum(class_counts, 1)
        class_weights = class_weights / class_weights.sum() * 2
    print(f'  class_weights: {class_weights.tolist()}', flush=True)

    # === Cross-validation ===
    n_total = len(y)
    gkf = GroupKFold(n_splits=n_splits)
    best_state, best_loss, best_epoch_count = None, float('inf'), 0
    fold_metrics = []

    for fi, (tr, va) in enumerate(gkf.split(np.zeros(n_total), y, groups=groups), start=1):
        print(f'\n  Fold {fi}/{n_splits} ({len(tr):,} train, {len(va):,} val)...', flush=True)
        t_fold = time.time()

        # Gather fold data via CPU index slicing (fast, contiguous)
        t0 = time.time()
        tr_size, tr_flag, tr_iat, tr_rtt, tr_ent = g_size[tr], g_flag[tr], g_iat[tr], g_rtt[tr], g_ent[tr]
        tr_static, tr_labels, tr_weights = g_static[tr], g_labels[tr], g_weights[tr]
        va_size, va_flag, va_iat, va_rtt, va_ent = g_size[va], g_flag[va], g_iat[va], g_rtt[va], g_ent[va]
        va_static, va_labels, va_weights = g_static[va], g_labels[va], g_weights[va]
        print(f'    Fold data gathered in {time.time()-t0:.1f}s', flush=True)

        model = DFI_CNN(num_classes=2).to(device)
        crit = nn.CrossEntropyLoss(weight=torch.tensor(class_weights, dtype=torch.float32).to(device), reduction='none')
        opt = torch.optim.Adam(model.parameters(), lr=lr)
        sch = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, patience=5, factor=0.5)

        best_fold, patience_count = float('inf'), 0

        for _epoch in range(epochs):
            train_loss = train_epoch(model, crit, opt, scaler, use_amp,
                                     tr_size, tr_flag, tr_iat, tr_rtt, tr_ent, tr_static, tr_labels, tr_weights,
                                     batch_size, device)
            val_loss, all_labels_np, all_preds_np = eval_epoch(model, crit, use_amp,
                                                                va_size, va_flag, va_iat, va_rtt, va_ent, va_static, va_labels, va_weights,
                                                                batch_size, device)
            sch.step(val_loss)

            if val_loss < best_fold:
                best_fold = val_loss
                patience_count = 0
                if val_loss < best_loss:
                    best_loss = val_loss
                    best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
                    best_epoch_count = _epoch + 1
            else:
                patience_count += 1
                if patience_count >= 10:
                    print(f'    Epoch {_epoch+1}: early stop (patience=10), val_loss={val_loss:.6f}', flush=True)
                    break

            if (_epoch + 1) % 5 == 0:
                print(f'    Epoch {_epoch+1}: train_loss={train_loss:.6f} val_loss={val_loss:.6f}', flush=True)

        rep = classification_report(all_labels_np, all_preds_np, labels=[0, 1], target_names=label_names, output_dict=True, zero_division=0)
        cm = confusion_matrix(all_labels_np, all_preds_np).tolist()
        fold_metrics.append({
            'fold': fi,
            'val_loss': best_fold,
            'accuracy': rep['accuracy'],
            'macro_f1': rep['macro avg']['f1-score'],
            'confusion_matrix': cm,
            'report': rep,
        })
        print(f'  Fold {fi}: val_loss={best_fold:.6f}  macro_f1={rep["macro avg"]["f1-score"]:.4f}  acc={rep["accuracy"]:.4f}  ({time.time()-t_fold:.0f}s)', flush=True)

        del tr_size, tr_flag, tr_iat, tr_rtt, tr_ent, tr_static, tr_labels, tr_weights
        del va_size, va_flag, va_iat, va_rtt, va_ent, va_static, va_labels, va_weights

    # === Retrain on full dataset ===
    print(f'\n  Retraining on full dataset ({n_total:,} rows, {best_epoch_count} epochs)...', flush=True)
    t_full = time.time()
    final_model = DFI_CNN(num_classes=2).to(device)
    final_crit = nn.CrossEntropyLoss(weight=torch.tensor(class_weights, dtype=torch.float32).to(device), reduction='none')
    final_opt = torch.optim.Adam(final_model.parameters(), lr=lr)
    final_scaler = torch.amp.GradScaler('cuda', enabled=use_amp)
    for ep in range(best_epoch_count):
        train_epoch(final_model, final_crit, final_opt, final_scaler, use_amp,
                    g_size, g_flag, g_iat, g_rtt, g_ent, g_static, g_labels, g_weights,
                    batch_size, device)
        if (ep + 1) % 5 == 0:
            print(f'    Full retrain epoch {ep+1}/{best_epoch_count}', flush=True)
    best_state = {k: v.detach().cpu().clone() for k, v in final_model.state_dict().items()}
    print(f'  Full retrain done in {time.time()-t_full:.0f}s', flush=True)

    # === Save ===
    os.makedirs(output_dir, exist_ok=True)
    ts = time.strftime('%Y%m%d_%H%M%S')
    model_path = os.path.join(output_dir, f'{model_prefix}_{ts}.pt')
    metrics_path = os.path.join(output_dir, f'{model_prefix}_{ts}_metrics.json')

    torch.save(best_state, model_path)
    with open(metrics_path, 'w', encoding='utf-8') as f:
        json.dump({
            'model': model_tag,
            'timestamp': ts,
            'n_samples': n_total,
            'epochs': epochs,
            'best_epoch_count': best_epoch_count,
            'batch_size': batch_size,
            'lr': lr,
            'scale_pos_weight': scale_pos_weight,
            'class_weights': class_weights.tolist(),
            'label_distribution': label_dist,
            'static_cols': CNN_STATIC_COLS,
            'folds': fold_metrics,
        }, f, indent=2)

    elapsed = time.time() - start
    print(f'\n  Training complete in {elapsed:.0f}s', flush=True)
    print(model_path)
    return model_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('csv')
    ap.add_argument('--epochs', type=int, default=50)
    ap.add_argument('--batch-size', type=int, default=512)
    ap.add_argument('--lr', type=float, default=1e-3)
    ap.add_argument('--folds', type=int, default=5)
    ap.add_argument('--output', '-o', default=OUTPUT_DIR)
    ap.add_argument('--evil', action='store_true', help='EVIL vs CLEAN binary classifier')
    ap.add_argument('--scale-pos-weight', type=float, default=1.0,
                    help='Weight multiplier for positive (attack) class (default: 1.0)')
    args = ap.parse_args()
    train_cnn(args.csv, args.epochs, args.batch_size, args.lr, args.folds, args.output,
              scale_pos_weight=args.scale_pos_weight, evil=args.evil)


if __name__ == '__main__':
    main()
