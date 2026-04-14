#!/usr/bin/env python3
"""One-shot score ALL PV1 flows with 5-class XGB, write to model_predictions.
Selects only needed columns. Processes in 500K chunks. Columnar insert.

Usage:
    python3 score_pv1_oneshot.py /opt/dfi2/ml/models/xgb_5class_v2.json
"""
import argparse
import time

import numpy as np
import pandas as pd
import xgboost as xgb
from clickhouse_driver import Client

MODEL_NAME = 'xgb_5class_v2'
CH_HOST = 'localhost'
CHUNK = 500000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('model', help='XGB model path')
    args = ap.parse_args()
    t0 = time.time()

    bst = xgb.Booster({'nthread': 80})
    bst.load_model(args.model)
    model_features = bst.feature_names
    model_version = args.model.split('/')[-1]
    print(f'Model: {model_version} ({len(model_features)} features)', flush=True)

    ch = Client(CH_HOST)
    total = ch.execute('SELECT count() FROM dfi.flows')[0][0]
    print(f'Total flows: {total:,}', flush=True)

    # Only select columns we need: identity + model features
    id_cols = ['flow_id', 'src_ip', 'dst_ip', 'dst_port', 'first_ts']
    select_cols = id_cols + [f for f in model_features if f not in id_cols]
    select_str = ', '.join(select_cols)

    scored = 0
    offset = 0
    while offset < total:
        query = f'SELECT {select_str} FROM dfi.flows ORDER BY first_ts LIMIT {CHUNK} OFFSET {offset}'
        rows = ch.execute(query, with_column_types=True)
        cols = [c[0] for c in rows[1]]
        data = rows[0]
        if not data:
            break

        df = pd.DataFrame(data, columns=cols)
        n = len(df)

        # Build feature matrix
        X = np.zeros((n, len(model_features)), dtype=np.float32)
        for i, feat in enumerate(model_features):
            if feat in df.columns:
                X[:, i] = pd.to_numeric(df[feat], errors='coerce').fillna(0).values

        # Score
        probs = bst.predict(xgb.DMatrix(X, feature_names=model_features, nthread=80))
        pred_labels = np.argmax(probs, axis=1).astype(np.uint8)
        pred_conf = np.max(probs, axis=1).astype(np.float32)

        # Columnar insert — no Python loop
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
    print(f'\nDone: {scored:,} predictions, {elapsed:.0f}s ({scored/elapsed:.0f} flows/s)', flush=True)


if __name__ == '__main__':
    main()
