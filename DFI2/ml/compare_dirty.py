#!/usr/bin/env python3
"""Compare CNN evil_02 vs XGB evil_01 on dirty.csv (all attacker/watchlist flows).

Metrics:
  - Flow-level: % flows detected as EVIL by each model
  - Per-IP: % of unique attacker IPs where >=1 flow detected
  - Agreement matrix: both/xgb-only/cnn-only/neither
  - Top IPs missed by both, found by CNN-only, found by XGB-only
"""
import sys
import time

import numpy as np
import pandas as pd
import polars as pl
import torch
import xgboost as xgb

sys.path.insert(0, '/nvme0n1-disk/ml')
from train_cnn import DFI_CNN

SEQ_LEN    = 128
BATCH_SIZE = 16384
DATA       = '/nvme0n1-disk/ml/data/dirty.csv'
CNN_MODEL     = '/nvme0n1-disk/ml/models/cnn_evil_20260307_122157.pt'
XGB_E1_MODEL  = '/nvme0n1-disk/ml/models/evil_20260306_181258.json'   # EVIL vs CLEAN
XGB_V7_MODEL  = '/nvme0n1-disk/ml/models/xgb_v7.json'                # ATTACK vs NORM
XGB_REC_MODEL = '/nvme0n1-disk/ml/models/xgb_recon_v3.json'          # RECON vs NORM

STATIC_COLS = [
    'dst_port', 'ip_proto', 'app_proto', 'pkts_fwd', 'pkts_rev', 'bytes_fwd', 'bytes_rev',
    'bytes_per_pkt_fwd', 'bytes_per_pkt_rev', 'pkt_ratio', 'byte_ratio', 'rtt_ms', 'n_events',
    'entropy_first', 'entropy_fwd_mean', 'entropy_rev_mean', 'printable_frac', 'null_frac',
    'byte_std', 'high_entropy_frac', 'payload_len_first', 'ja3_freq', 'tls_version',
    'tls_cipher_count', 'tls_ext_count', 'tls_has_sni', 'hassh_freq', 'ssh_kex_count',
    'http_method', 'http_uri_len', 'http_header_count', 'http_ua_freq', 'http_has_body',
    'http_status', 'dns_qtype', 'dns_qname_len', 'src_flow_count', 'src_unique_ports',
    'src_unique_protos', 'src_unique_dsts', 'src_span_min', 'src_avg_pps',
]
ZERO_FILL_COLS = [
    'ja3_freq', 'tls_version', 'tls_cipher_count', 'tls_ext_count', 'tls_has_sni',
    'hassh_freq', 'ssh_kex_count', 'http_method', 'http_uri_len', 'http_header_count',
    'http_ua_freq', 'http_has_body', 'http_status', 'dns_qtype', 'dns_qname_len',
    'src_flow_count', 'src_unique_ports', 'src_unique_protos', 'src_unique_dsts',
    'src_span_min', 'src_avg_pps',
]
PKT_SET = {'pkt_size_dir', 'pkt_flag', 'pkt_iat_log_ms', 'pkt_iat_rtt', 'pkt_entropy',
           'actor_id', 'label', 'label_confidence',
           'src_ip', 'dst_ip', 'flow_id', 'session_key', 'first_ts', 'last_ts', 'evidence_detail'}

# ── Load ──────────────────────────────────────────────────────────────────────
print('Loading dirty.csv...', flush=True)
t0 = time.time()
df_pl = pl.read_csv(DATA, infer_schema_length=0, null_values=[r'\N', ''], try_parse_dates=False)
casts = [pl.col(c).cast(pl.Float64, strict=False)
         for c in df_pl.columns if c not in PKT_SET and df_pl[c].dtype == pl.Utf8]
if casts:
    df_pl = df_pl.with_columns(casts)
n = len(df_pl)
print(f'  {n:,} rows ({time.time()-t0:.1f}s)', flush=True)

actor_ids = df_pl['actor_id'].fill_null('unknown').to_numpy()
src_ips   = df_pl['src_ip'].fill_null('unknown').to_numpy()

# ── Expand pkt_* sequences (polars — fast) ────────────────────────────────────
def expand_channel(df, col, seq_len=SEQ_LEN):
    parsed = df[col].str.strip_chars('[]').str.split(',')
    cols = [parsed.list.get(i, null_on_oob=True).cast(pl.Int64, strict=False).fill_null(0)
            for i in range(seq_len)]
    return pl.DataFrame(dict(zip([f'_{i}' for i in range(seq_len)], cols))).to_numpy()

print('Expanding pkt_* sequences...', flush=True)
t0 = time.time()
np_size_raw = expand_channel(df_pl, 'pkt_size_dir')
np_size = np.where(np_size_raw == 0, 0, np_size_raw + 12).astype(np.int64)  # +12 offset
np_flag = expand_channel(df_pl, 'pkt_flag').astype(np.int64)
np_iat  = expand_channel(df_pl, 'pkt_iat_log_ms').astype(np.int64)
np_rtt  = expand_channel(df_pl, 'pkt_iat_rtt').astype(np.int64)
np_ent  = expand_channel(df_pl, 'pkt_entropy').astype(np.int64)
print(f'  Sequences expanded in {time.time()-t0:.1f}s', flush=True)

# ── Build scalar feature matrix ───────────────────────────────────────────────
df_pd = df_pl.to_pandas()
del df_pl

# Derived features
df_pd['bytes_per_pkt_fwd'] = np.where(df_pd['pkts_fwd'].fillna(0) > 0,
                                       df_pd['bytes_fwd'].fillna(0) / df_pd['pkts_fwd'], 0)
df_pd['bytes_per_pkt_rev'] = np.where(df_pd['pkts_rev'].fillna(0) > 0,
                                       df_pd['bytes_rev'].fillna(0) / df_pd['pkts_rev'], 0)
tp = df_pd['pkts_fwd'].fillna(0) + df_pd['pkts_rev'].fillna(0)
df_pd['pkt_ratio']  = np.where(tp > 0, df_pd['pkts_fwd'].fillna(0) / tp, 0)
tb = df_pd['bytes_fwd'].fillna(0) + df_pd['bytes_rev'].fillna(0)
df_pd['byte_ratio'] = np.where(tb > 0, df_pd['bytes_fwd'].fillna(0) / tb, 0)
for col in ZERO_FILL_COLS:
    df_pd[col] = 0

np_static = df_pd[STATIC_COLS].fillna(0).values.astype(np.float32)

def run_xgb(model_path, label, df_pd, n):
    print(f'\n--- {label} ---', flush=True)
    t0 = time.time()
    m = xgb.Booster({'nthread': 72})
    m.load_model(model_path)
    feats = m.feature_names
    for f in feats:
        if f not in df_pd.columns:
            df_pd[f] = 0
    dmat = xgb.DMatrix(df_pd[feats].fillna(0).values.astype(np.float32),
                       feature_names=feats, nthread=72)
    prob = m.predict(dmat)
    pred = (prob > 0.5).astype(int)
    print(f'  Scored {n:,} flows in {time.time()-t0:.1f}s', flush=True)
    del dmat, m
    return pred, prob

xgb_e1_pred,  xgb_e1_prob  = run_xgb(XGB_E1_MODEL,  'XGB evil_01 (EVIL vs CLEAN)',  df_pd, n)
xgb_v7_pred,  xgb_v7_prob  = run_xgb(XGB_V7_MODEL,  'XGB v7 (ATTACK vs NORM)',      df_pd, n)
xgb_rec_pred, xgb_rec_prob = run_xgb(XGB_REC_MODEL, 'XGB recon_v3 (RECON vs NORM)', df_pd, n)

# ── CNN evil_02 ───────────────────────────────────────────────────────────────
print('\n--- CNN evil_02 ---', flush=True)
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
cnn_model = DFI_CNN(num_classes=2).to(device)
state = torch.load(CNN_MODEL, map_location=device, weights_only=True)
cnn_model.load_state_dict(state)
cnn_model.eval()

t0 = time.time()
cnn_pred = np.zeros(n, dtype=np.int64)
cnn_prob = np.zeros(n, dtype=np.float32)

with torch.no_grad():
    for i in range(0, n, BATCH_SIZE):
        end = min(i + BATCH_SIZE, n)
        size_t = torch.tensor(np_size[i:end], dtype=torch.long).to(device)
        flag_t = torch.tensor(np_flag[i:end], dtype=torch.long).to(device)
        iat_t  = torch.tensor(np_iat[i:end],  dtype=torch.long).to(device)
        rtt_t  = torch.tensor(np_rtt[i:end],  dtype=torch.long).to(device)
        ent_t  = torch.tensor(np_ent[i:end],  dtype=torch.long).to(device)
        stat_t = torch.tensor(np_static[i:end], dtype=torch.float32).to(device)
        logits = cnn_model(size_t, flag_t, iat_t, rtt_t, ent_t, stat_t)
        probs  = torch.softmax(logits, dim=1).cpu().numpy()
        cnn_pred[i:end] = np.argmax(probs, axis=1)
        cnn_prob[i:end] = probs[:, 1]
        if (i // BATCH_SIZE) % 20 == 0:
            print(f'  CNN {end:,}/{n:,}', flush=True)

print(f'  CNN scored in {time.time()-t0:.1f}s', flush=True)

# ── Report ────────────────────────────────────────────────────────────────────
def flow_report(name, pred, prob, cnn_pred, cnn_prob, n):
    evil = int(pred.sum())
    print(f'  {name}: {evil:,}/{n:,} = {100*evil/n:.1f}%  (avg conf {prob[pred==1].mean():.3f})')

def agreement_row(a_name, a_pred, b_name, b_pred, n):
    both  = int(((a_pred==1)&(b_pred==1)).sum())
    a_only= int(((a_pred==1)&(b_pred==0)).sum())
    b_only= int(((a_pred==0)&(b_pred==1)).sum())
    none  = int(((a_pred==0)&(b_pred==0)).sum())
    print(f'    Both:  {both:,} ({100*both/n:.1f}%)  '
          f'{a_name} only: {a_only:,} ({100*a_only/n:.1f}%)  '
          f'{b_name} only: {b_only:,} ({100*b_only/n:.1f}%)  '
          f'Neither: {none:,} ({100*none/n:.1f}%)')

print(f'\n{"="*60}')
print(f'FLOW-LEVEL DETECTION  ({n:,} dirty/watchlist flows)')
print(f'  Ground truth: ALL from watchlist attacker IPs')
print(f'{"="*60}')
flow_report('XGB v7       (ATTACK/NORM)', xgb_v7_pred,  xgb_v7_prob,  cnn_pred, cnn_prob, n)
flow_report('XGB recon_v3  (RECON/NORM)', xgb_rec_pred, xgb_rec_prob, cnn_pred, cnn_prob, n)
flow_report('XGB evil_01  (EVIL/CLEAN)',  xgb_e1_pred,  xgb_e1_prob,  cnn_pred, cnn_prob, n)
flow_report('CNN evil_02  (EVIL/CLEAN)',  cnn_pred,     cnn_prob,     cnn_pred, cnn_prob, n)

print(f'\n  Pairwise vs CNN:')
print(f'  v7   vs CNN: ', end=''); agreement_row('v7',   xgb_v7_pred,  'CNN', cnn_pred, n)
print(f'  recon vs CNN:', end=''); agreement_row('recon',xgb_rec_pred, 'CNN', cnn_pred, n)
print(f'  e1   vs CNN: ', end=''); agreement_row('e1',   xgb_e1_pred,  'CNN', cnn_pred, n)

any_xgb  = ((xgb_v7_pred==1)|(xgb_e1_pred==1)|(xgb_rec_pred==1)).astype(int)
all_four = ((xgb_v7_pred==1)&(xgb_e1_pred==1)&(xgb_rec_pred==1)&(cnn_pred==1)).astype(int)
none_all = ((xgb_v7_pred==0)&(xgb_e1_pred==0)&(xgb_rec_pred==0)&(cnn_pred==0)).astype(int)
print(f'\n  Any XGB flags:     {int(any_xgb.sum()):,} ({100*any_xgb.mean():.1f}%)')
print(f'  All 4 agree EVIL:  {int(all_four.sum()):,} ({100*all_four.mean():.1f}%)')
print(f'  All 4 agree CLEAN: {int(none_all.sum()):,} ({100*none_all.mean():.1f}%) ← missed by all')

# Per-IP
results = pd.DataFrame({
    'src_ip':   src_ips,
    'v7_pred':  xgb_v7_pred,  'v7_prob':  xgb_v7_prob,
    'rec_pred': xgb_rec_pred, 'rec_prob': xgb_rec_prob,
    'e1_pred':  xgb_e1_pred,  'e1_prob':  xgb_e1_prob,
    'cnn_pred': cnn_pred,     'cnn_prob': cnn_prob,
})
per_ip = results.groupby('src_ip').agg(
    n_flows  =('cnn_pred','count'),
    v7_evil  =('v7_pred','sum'),  v7_max  =('v7_prob','max'),
    rec_evil =('rec_pred','sum'), rec_max =('rec_prob','max'),
    e1_evil  =('e1_pred','sum'),  e1_max  =('e1_prob','max'),
    cnn_evil =('cnn_pred','sum'), cnn_max =('cnn_prob','max'),
)
per_ip['v7_det']  = per_ip['v7_evil']  > 0
per_ip['rec_det'] = per_ip['rec_evil'] > 0
per_ip['e1_det']  = per_ip['e1_evil']  > 0
per_ip['cnn_det'] = per_ip['cnn_evil'] > 0
per_ip['any_xgb'] = per_ip['v7_det'] | per_ip['rec_det'] | per_ip['e1_det']
n_ips = len(per_ip)

print(f'\n{"="*60}')
print(f'PER-IP DETECTION  ({n_ips:,} unique attacker IPs)')
print(f'{"="*60}')
for col, label in [('v7_det','XGB v7'), ('rec_det','XGB recon_v3'),
                   ('e1_det','XGB evil_01'), ('cnn_det','CNN evil_02'), ('any_xgb','Any XGB (union)')]:
    cnt = int(per_ip[col].sum())
    print(f'  {label:22s}: {cnt:,}/{n_ips:,} = {100*cnt/n_ips:.1f}%')

all_det    = int((per_ip.v7_det & per_ip.rec_det & per_ip.e1_det & per_ip.cnn_det).sum())
none_det   = int((~per_ip.v7_det & ~per_ip.rec_det & ~per_ip.e1_det & ~per_ip.cnn_det).sum())
cnn_only_n = int((~per_ip.any_xgb & per_ip.cnn_det).sum())
print(f'\n  All 4 detect:       {all_det:,} ({100*all_det/n_ips:.1f}%)')
print(f'  CNN only (no XGB):  {cnn_only_n:,} ({100*cnn_only_n/n_ips:.1f}%)')
print(f'  None detect:        {none_det:,} ({100*none_det/n_ips:.1f}%)')

missed = per_ip[~per_ip.v7_det & ~per_ip.rec_det & ~per_ip.e1_det & ~per_ip.cnn_det].sort_values('n_flows', ascending=False)
if len(missed):
    print(f'\n  IPs missed by ALL 4:')
    for ip, row in missed.head(10).iterrows():
        print(f'    {ip}: {int(row.n_flows)} flows  v7={row.v7_max:.3f}  rec={row.rec_max:.3f}  e1={row.e1_max:.3f}  cnn={row.cnn_max:.3f}')

cnn_only_df = per_ip[~per_ip.any_xgb & per_ip.cnn_det].sort_values('n_flows', ascending=False)
if len(cnn_only_df):
    print(f'\n  IPs CNN found, all XGBs missed (top 10):')
    for ip, row in cnn_only_df.head(10).iterrows():
        print(f'    {ip}: {int(row.n_flows)} flows  cnn_evil={int(row.cnn_evil)}  cnn_max={row.cnn_max:.3f}  v7={row.v7_max:.3f}  rec={row.rec_max:.3f}')

rec_only_df = per_ip[per_ip.rec_det & ~per_ip.v7_det & ~per_ip.e1_det & ~per_ip.cnn_det].sort_values('n_flows', ascending=False)
if len(rec_only_df):
    print(f'\n  IPs recon_v3 only (missed by v7, e1, CNN):')
    for ip, row in rec_only_df.head(10).iterrows():
        print(f'    {ip}: {int(row.n_flows)} flows  rec_max={row.rec_max:.3f}')

print(f'\nDone.', flush=True)
