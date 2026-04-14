#!/usr/bin/env python3
"""One-shot score ALL PV1 flows with 3-class CNN, write to model_predictions.
50K chunks, select only needed cols, columnar insert. CPU 80 threads.

Usage:
    python3 score_pv1_cnn_oneshot.py /opt/dfi2/ml/models/cnn_3class_v1.pt
"""
import argparse
import time

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from clickhouse_driver import Client

MODEL_NAME = 'cnn_3class_v1'
CH_HOST = 'localhost'
CHUNK = 50000
SEQ_LEN = 128

STATIC_COLS = [
    'dst_port', 'ip_proto', 'app_proto', 'pkts_fwd', 'pkts_rev', 'bytes_fwd', 'bytes_rev',
    'rtt_ms', 'n_events', 'duration_ms', 'pps', 'bps',
    'entropy_first', 'entropy_fwd_mean', 'entropy_rev_mean', 'printable_frac', 'null_frac',
    'byte_std', 'high_entropy_frac', 'payload_len_first',
    'fwd_size_mean', 'fwd_size_std', 'fwd_size_min', 'fwd_size_max',
    'rev_size_mean', 'rev_size_std', 'rev_size_max',
    'hist_tiny', 'hist_small', 'hist_medium', 'hist_large', 'hist_full', 'frac_full',
    'syn_count', 'fin_count', 'rst_count', 'psh_count', 'ack_only_count',
    'conn_state', 'rst_frac', 'syn_to_data', 'psh_burst_max', 'retransmit_est', 'window_size_init',
    'iat_fwd_mean_ms', 'iat_fwd_std_ms', 'think_time_mean_ms', 'think_time_std_ms',
    'iat_to_rtt', 'payload_rtt_ratio',
]

CNN_COLS = ['pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy']
ID_COLS = ['flow_id', 'src_ip', 'dst_ip', 'dst_port', 'first_ts']


class DFI_CNN(nn.Module):
    def __init__(self, num_classes=3, n_static=50):
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
        self.static_bn = nn.BatchNorm1d(n_static)
        self.head = nn.Sequential(nn.Linear(128 + n_static, 128), nn.ReLU(), nn.Dropout(0.3), nn.Linear(128, num_classes))

    def forward(self, size_seq, flag_seq, iat_seq, rtt_seq, ent_seq, static_feat):
        s = self.size_emb(size_seq)
        f = self.flag_emb(flag_seq)
        i = self.iat_emb(iat_seq)
        r = self.rtt_emb(rtt_seq)
        e = self.ent_emb(ent_seq)
        x = torch.cat([s, f, i, r, e], dim=2).transpose(1, 2)
        x = x * (size_seq != 0).unsqueeze(1).float()
        x = torch.cat([self.conv3(x), self.conv5(x), self.conv7(x)], dim=1)
        x = self.merge(x).squeeze(2)
        return self.head(torch.cat([x, self.static_bn(static_feat)], dim=1))


def expand_arrays(df, col, length=128):
    """Expand CH Array(Int8) column to numpy. CH returns Python lists."""
    n = len(df)
    out = np.zeros((n, length), dtype=np.int64)
    vals = df[col].values
    for i in range(n):
        v = vals[i]
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            m = min(len(v), length)
            for j in range(m):
                out[i, j] = int(v[j])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('model', help='CNN model .pt path')
    args = ap.parse_args()
    t0 = time.time()

    torch.set_num_threads(80)
    n_static = len(STATIC_COLS)
    model = DFI_CNN(num_classes=3, n_static=n_static)
    model.load_state_dict(torch.load(args.model, map_location='cpu', weights_only=True))
    model.eval()
    model_version = args.model.split('/')[-1]
    print(f'Model: {model_version} (CPU, {torch.get_num_threads()} threads)', flush=True)

    ch = Client(CH_HOST)
    total = ch.execute('SELECT count() FROM dfi.flows')[0][0]
    print(f'Total flows: {total:,}', flush=True)

    # Select only needed columns
    select_cols = ID_COLS + STATIC_COLS + CNN_COLS
    # Deduplicate
    seen = set()
    unique_cols = []
    for c in select_cols:
        if c not in seen:
            unique_cols.append(c)
            seen.add(c)
    select_str = ', '.join(unique_cols)

    scored = 0
    offset = 0
    while offset < total:
        rows = ch.execute(
            f'SELECT {select_str} FROM dfi.flows ORDER BY first_ts LIMIT {CHUNK} OFFSET {offset}',
            with_column_types=True,
        )
        cols = [c[0] for c in rows[1]]
        data = rows[0]
        if not data:
            break

        df = pd.DataFrame(data, columns=cols)
        df = df.loc[:, ~df.columns.duplicated()]
        n = len(df)

        # Expand CNN arrays
        np_size_raw = expand_arrays(df, 'pkt_size_dir')
        np_size = np.where(np_size_raw == 0, 0, np_size_raw + 12).astype(np.int64)
        np_flag = expand_arrays(df, 'pkt_flag')
        np_iat = expand_arrays(df, 'pkt_iat_log_ms')
        np_rtt = expand_arrays(df, 'pkt_iat_rtt')
        np_ent = expand_arrays(df, 'pkt_entropy')

        # Static features
        avail = [c for c in STATIC_COLS if c in df.columns]
        for c in avail:
            if df[c].dtype == object:
                df[c] = pd.to_numeric(df[c], errors='coerce')
        np_static = df[avail].fillna(0).values.astype(np.float32)
        if len(avail) < n_static:
            np_static = np.concatenate([np_static, np.zeros((n, n_static - len(avail)), dtype=np.float32)], axis=1)

        # Score in sub-batches
        all_probs = []
        batch = 8192
        with torch.no_grad():
            for i in range(0, n, batch):
                e = min(i + batch, n)
                logits = model(
                    torch.tensor(np_size[i:e], dtype=torch.long),
                    torch.tensor(np_flag[i:e], dtype=torch.long),
                    torch.tensor(np_iat[i:e], dtype=torch.long),
                    torch.tensor(np_rtt[i:e], dtype=torch.long),
                    torch.tensor(np_ent[i:e], dtype=torch.long),
                    torch.tensor(np_static[i:e], dtype=torch.float32),
                )
                all_probs.append(torch.softmax(logits, dim=1).numpy())

        probs = np.concatenate(all_probs)
        pred_labels = np.argmax(probs, axis=1).astype(np.uint8)
        pred_conf = np.max(probs, axis=1).astype(np.float32)

        # Columnar insert
        flow_ids = df['flow_id'].astype(str).tolist()
        src_ips = df['src_ip'].astype(str).tolist()
        dst_ips = df['dst_ip'].astype(str).tolist()
        dst_ports = df['dst_port'].astype(int).tolist()
        first_ts = df['first_ts'].tolist()
        class_probs = [list(map(float, p)) for p in probs]

        ch.execute(
            'INSERT INTO dfi.model_predictions '
            '(flow_id, src_ip, dst_ip, dst_port, flow_first_ts, '
            'model_name, model_version, label, confidence, class_probs, scored_at) VALUES',
            list(zip(
                flow_ids, src_ips, dst_ips, dst_ports, first_ts,
                [MODEL_NAME] * n, [model_version] * n,
                pred_labels.tolist(), pred_conf.tolist(), class_probs, first_ts,
            ))
        )

        scored += n
        offset += CHUNK
        elapsed = time.time() - t0
        rate = scored / elapsed if elapsed > 0 else 0
        print(f'  {scored:,}/{total:,} ({scored/total*100:.1f}%) {rate:.0f} flows/s', flush=True)

    elapsed = time.time() - t0
    print(f'\nDone: {scored:,} CNN predictions, {elapsed:.0f}s ({scored/elapsed:.0f} flows/s)', flush=True)


if __name__ == '__main__':
    main()
