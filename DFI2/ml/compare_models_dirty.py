#!/usr/bin/env python3
"""Side-by-side comparison of all XGB models against dirty.csv."""
import paramiko, textwrap

HOST = '69.197.168.155'
USER = 'administrator'
PASS = r'CHANGE_ME'

SCRIPT = textwrap.dedent(r"""
import polars as pl
import xgboost as xgb
import numpy as np

DATA = '/nvme0n1-disk/ml/data/dirty.csv'
MODELS = {
    'recon_v3':    '/nvme0n1-disk/ml/models/xgb_recon_v3.json',
    'v7':          '/nvme0n1-disk/ml/models/xgb_v7.json',
    'evil_01':     '/nvme0n1-disk/ml/models/evil_20260306_181258.json',
    'evidence_01': '/nvme0n1-disk/ml/models/evidence_20260307_174251.json',
}

print('Loading dirty.csv...')
df = pl.read_csv(DATA, infer_schema_length=10000, null_values=[r'\N', 'NULL', ''])
total_flows = len(df)
print(f'  {total_flows:,} flows, {len(df.columns)} cols')

results = {}  # model_name -> pred array

for name, path in MODELS.items():
    bst = xgb.Booster()
    bst.load_model(path)
    feat_names = bst.feature_names

    X = np.zeros((total_flows, len(feat_names)), dtype=np.float32)
    for i, col in enumerate(feat_names):
        if col in df.columns:
            X[:, i] = df[col].cast(pl.Float32, strict=False).fill_null(0).to_numpy()

    dm = xgb.DMatrix(X, feature_names=feat_names, nthread=72)
    proba = bst.predict(dm)
    pred  = (proba >= 0.5).astype(np.int8)
    results[name] = pred
    print(f'  Scored {name}: {int(pred.sum()):,} detected ({pred.mean()*100:.1f}%)')

# Build IP-level table
src_ips = df['src_ip'].to_numpy()
unique_ips = np.unique(src_ips)
total_ips = len(unique_ips)

# Per-IP: total flows + detected per model
ip_flows = {}
for ip in unique_ips:
    ip_flows[ip] = int((src_ips == ip).sum())

ip_det = {name: {} for name in MODELS}
for name, pred in results.items():
    for ip in unique_ips:
        mask = src_ips == ip
        ip_det[name][ip] = int(pred[mask].sum())

# Summary table
print(f'\n{"="*70}')
print(f'MODEL COMPARISON vs dirty.csv  ({total_flows:,} flows, {total_ips:,} IPs)')
print(f'{"="*70}')
print(f'{"Model":<14} {"Flows det":>10} {"Flow%":>7} {"IPs det":>9} {"IP%":>7} {"Missed":>7}')
print(f'{"-"*14} {"-"*10} {"-"*7} {"-"*9} {"-"*7} {"-"*7}')

model_detected_ips = {}
for name, pred in results.items():
    flow_det = int(pred.sum())
    det_ips = sum(1 for ip in unique_ips if ip_det[name][ip] > 0)
    missed  = total_ips - det_ips
    model_detected_ips[name] = set(ip for ip in unique_ips if ip_det[name][ip] > 0)
    print(f'{name:<14} {flow_det:>10,} {flow_det/total_flows*100:>7.1f}% {det_ips:>9,} {det_ips/total_ips*100:>7.1f}% {missed:>7,}')

# Any-model union
any_det_ips = set().union(*model_detected_ips.values())
any_pred = np.zeros(total_flows, dtype=np.int8)
for pred in results.values():
    any_pred = np.maximum(any_pred, pred)
any_flow_det = int(any_pred.sum())
print(f'{"ANY model":<14} {any_flow_det:>10,} {any_flow_det/total_flows*100:>7.1f}% {len(any_det_ips):>9,} {len(any_det_ips)/total_ips*100:>7.1f}% {total_ips-len(any_det_ips):>7,}')

# IPs missed by ALL models
missed_all = set(unique_ips) - any_det_ips
print(f'\nIPs missed by ALL models ({len(missed_all)}):')
missed_rows = sorted([(ip, ip_flows[ip]) for ip in missed_all], key=lambda x: -x[1])
for ip, flows in missed_rows[:30]:
    print(f'  {ip:<22} {flows:>6} flows')
if len(missed_rows) > 30:
    print(f'  ... ({len(missed_rows)-30} more)')

# IPs caught by evidence_01 but missed by evil_01
ev_only = model_detected_ips['evidence_01'] - model_detected_ips['evil_01']
print(f'\nIPs caught by evidence_01 but NOT evil_01 ({len(ev_only)}):')
for ip in sorted(ev_only, key=lambda ip: -ip_det['evidence_01'][ip])[:20]:
    print(f'  {ip:<22}  evidence={ip_det["evidence_01"][ip]:>5}  evil={ip_det["evil_01"][ip]:>5}  v7={ip_det["v7"][ip]:>5}  flows={ip_flows[ip]:>6}')

# IPs caught by evil_01 but missed by evidence_01
evil_only = model_detected_ips['evil_01'] - model_detected_ips['evidence_01']
print(f'\nIPs caught by evil_01 but NOT evidence_01 ({len(evil_only)}):')
for ip in sorted(evil_only, key=lambda ip: -ip_det['evil_01'][ip])[:20]:
    print(f'  {ip:<22}  evil={ip_det["evil_01"][ip]:>5}  evidence={ip_det["evidence_01"][ip]:>5}  flows={ip_flows[ip]:>6}')
""")

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, 22, USER, PASS, timeout=30)

sftp = c.open_sftp()
with sftp.open('/tmp/_compare_models_dirty.py', 'w') as f:
    f.write(SCRIPT)
sftp.close()

VENV = '/nvme0n1-disk/ml/venv/bin/python3'
_, out, err = c.exec_command(f'{VENV} /tmp/_compare_models_dirty.py 2>&1')
out.channel.recv_exit_status()
print(out.read().decode())
c.close()
