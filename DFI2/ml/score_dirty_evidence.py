#!/usr/bin/env python3
"""Score dirty.csv with evidence_01 model, report per-IP detection."""
import paramiko, textwrap

HOST = '69.197.168.155'
USER = 'administrator'
PASS = r'CHANGE_ME'

SCRIPT = textwrap.dedent(r"""
import polars as pl
import xgboost as xgb
import numpy as np
import glob

MODEL_DIR = '/nvme0n1-disk/ml/models'
DATA      = '/nvme0n1-disk/ml/data/dirty.csv'

models = sorted(m for m in glob.glob(f'{MODEL_DIR}/evidence_*.json') if '_metrics' not in m)
model_path = models[-1]
print(f'Model: {model_path}')

bst = xgb.Booster()
bst.load_model(model_path)
feat_names = bst.feature_names
print(f'Model features: {len(feat_names)}')

df = pl.read_csv(DATA, infer_schema_length=10000, null_values=[r'\N', 'NULL', ''])
print(f'Dirty rows: {len(df):,}  cols: {len(df.columns)}')

X = np.zeros((len(df), len(feat_names)), dtype=np.float32)
for i, col in enumerate(feat_names):
    if col in df.columns:
        X[:, i] = df[col].cast(pl.Float32, strict=False).fill_null(0).to_numpy()

dm = xgb.DMatrix(X, feature_names=feat_names, nthread=72)
proba = bst.predict(dm)
pred  = (proba >= 0.5).astype(int)

df = df.with_columns([
    pl.Series('evidence_score', proba),
    pl.Series('evidence_pred',  pred),
])

ip_col = 'src_ip' if 'src_ip' in df.columns else None
if ip_col:
    ip_stats = (
        df.group_by(ip_col)
          .agg([
              pl.len().alias('flows'),
              pl.col('evidence_pred').sum().alias('detected_flows'),
          ])
          .with_columns(
              (pl.col('detected_flows') / pl.col('flows')).alias('detect_rate')
          )
          .sort('detected_flows', descending=True)
    )
    detected_ips = ip_stats.filter(pl.col('detected_flows') > 0)
    missed_ips   = ip_stats.filter(pl.col('detected_flows') == 0)

    total_flows  = len(df)
    det_flows    = int(pred.sum())
    total_ips    = ip_stats.shape[0]

    print(f'\n=== Evidence_01 vs Dirty.csv ===')
    print(f'Total flows:    {total_flows:,}')
    print(f'Detected flows: {det_flows:,}  ({det_flows/total_flows*100:.1f}%)')
    print(f'Total IPs:      {total_ips:,}')
    print(f'Detected IPs:   {detected_ips.shape[0]:,}  ({detected_ips.shape[0]/total_ips*100:.1f}%)')
    print(f'Missed IPs:     {missed_ips.shape[0]:,}')
    print(f'\nTop 40 detected IPs (by flow count):')
    print(detected_ips.head(40).to_pandas().to_string(index=False))
    if missed_ips.shape[0] > 0:
        print(f'\nMissed IPs (0 flows detected):')
        print(missed_ips.select([ip_col,'flows']).to_pandas().to_string(index=False))
else:
    det_flows = int(pred.sum())
    print(f'No src_ip col. Detected {det_flows:,}/{len(df):,} flows ({det_flows/len(df)*100:.1f}%)')
""")

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, 22, USER, PASS, timeout=30)

sftp = c.open_sftp()
with sftp.open('/tmp/_score_dirty_evidence.py', 'w') as f:
    f.write(SCRIPT)
sftp.close()

VENV = '/nvme0n1-disk/ml/venv/bin/python3'
_, out, err = c.exec_command(f'{VENV} /tmp/_score_dirty_evidence.py 2>&1')
out.channel.recv_exit_status()
print(out.read().decode())
c.close()
