#!/usr/bin/env python3
"""Test all 3 binary XGB models against unseen ClickHouse data."""
import json
import os
import subprocess
import time

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix

MODEL_DIR = '/mnt/dfi-data/ml/models'
TEST_CSV = '/mnt/dfi-data/ml/data/test_mar01.csv'

CH_QUERY = """
SELECT v.* FROM dfi.v_xgb v
INNER JOIN dfi.flows f ON v.`f.flow_id` = f.flow_id
WHERE f.first_ts >= '2026-03-01 00:00:00'
FORMAT CSVWithNames
"""

ID_COLS = ['f.flow_id', 'flow_id', 'session_key', 'actor_id']
META_COLS = ['label_confidence', 'evidence_mask', 'evidence_detail']
TARGET = 'label'

MODELS = [
    {
        'name': 'SCAN (Model 1)',
        'file': 'xgb_20260302_003848.json',
        'labels': ['SCAN', 'ATTACK'],
        'remap': lambda y: (y != 0).astype(np.int32),
    },
    {
        'name': 'BRUTEFORCE (Model 2)',
        'file': 'xgb_20260302_022155.json',
        'labels': ['NOT_BRUTEFORCE', 'BRUTEFORCE'],
        'remap': lambda y: (y == 1).astype(np.int32),
    },
    {
        'name': 'EXPLOIT (Model 3)',
        'file': 'xgb_20260302_033432.json',
        'labels': ['NOT_EXPLOIT', 'EXPLOIT'],
        'remap': lambda y: (y == 2).astype(np.int32),
    },
]


def export_test_data():
    """Export test data from CH via clickhouse-client CLI."""
    if os.path.exists(TEST_CSV):
        lines = sum(1 for _ in open(TEST_CSV))
        if lines > 100:
            print(f'Test CSV already exists: {TEST_CSV} ({lines:,} lines), skipping export')
            return

    print('=== Exporting test data from ClickHouse ===')
    t0 = time.time()
    with open(TEST_CSV, 'w') as f:
        subprocess.run(
            ['clickhouse-client', '--query', CH_QUERY.strip(),
             '--max_threads', '0', '--max_memory_usage', '0'],
            stdout=f, check=True,
        )
    lines = sum(1 for _ in open(TEST_CSV))
    print(f'Exported {lines-1:,} rows in {time.time()-t0:.1f}s')


def main():
    export_test_data()

    print('\n=== Loading test CSV ===')
    t0 = time.time()
    df = pd.read_csv(TEST_CSV, engine='pyarrow', na_values=[r'\N'])
    df.columns = [c.replace('f.', '') for c in df.columns]
    print(f'Loaded {len(df):,} rows in {time.time()-t0:.1f}s')
    print(f'Label distribution (raw): {dict(df[TARGET].value_counts().sort_index())}')

    feat_cols = [c for c in df.columns if c not in ID_COLS + META_COLS + [TARGET]]
    for c in feat_cols:
        if df[c].dtype == object:
            df[c] = pd.to_numeric(df[c], errors='coerce')

    X = df[feat_cols]
    y_raw = df[TARGET].values
    print(f'Features: {len(feat_cols)}')
    print(f'Building DMatrix...')
    dmat = xgb.DMatrix(X, enable_categorical=False, nthread=80)

    results = {}
    for m in MODELS:
        print(f'\n{"="*60}')
        print(f'  {m["name"]}')
        print(f'{"="*60}')

        model = xgb.Booster()
        model.load_model(f'{MODEL_DIR}/{m["file"]}')
        model.set_param({'nthread': 80})

        y_true = m['remap'](y_raw)
        y_prob = model.predict(dmat)
        y_pred = (y_prob > 0.5).astype(int)

        print(f'\nClass distribution: {m["labels"][0]}={int((y_true==0).sum()):,}  {m["labels"][1]}={int((y_true==1).sum()):,}')
        print(f'\nClassification Report:')
        print(classification_report(y_true, y_pred, labels=[0, 1],
              target_names=m['labels'], zero_division=0))

        cm = confusion_matrix(y_true, y_pred)
        print(f'Confusion Matrix:')
        print(f'  {"":>18} Pred {m["labels"][0]:>15} Pred {m["labels"][1]:>15}')
        print(f'  True {m["labels"][0]:>12}  {cm[0][0]:>15,}  {cm[0][1]:>15,}')
        print(f'  True {m["labels"][1]:>12}  {cm[1][0]:>15,}  {cm[1][1]:>15,}')

        if cm[1].sum() > 0:
            recall = cm[1][1] / cm[1].sum()
            precision = cm[1][1] / max(cm[:, 1].sum(), 1)
            print(f'\n  >>> {m["labels"][1]} recall:    {recall:.4f} ({cm[1][1]:,}/{cm[1].sum():,})')
            print(f'  >>> {m["labels"][1]} precision: {precision:.4f}')

        results[m['name']] = {
            'confusion_matrix': cm.tolist(),
            'report': classification_report(y_true, y_pred, labels=[0, 1],
                      target_names=m['labels'], output_dict=True, zero_division=0),
        }

    with open(f'{MODEL_DIR}/test_results_mar01.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f'\nResults saved to {MODEL_DIR}/test_results_mar01.json')


if __name__ == '__main__':
    main()
