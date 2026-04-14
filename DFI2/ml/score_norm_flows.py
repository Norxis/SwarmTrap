#!/usr/bin/env python3
"""Score flows by label with a selectable XGB model.

Writes progress to /tmp/norm_rescore/status.json for the backend API to read.
Uses clickhouse-client TSV + pyarrow (benchmark winner: 42K/s).
"""
import argparse
import gc
import json
import os
import subprocess
import sys
import time

import numpy as np
import pandas as pd
import pyarrow.csv as pcsv
import xgboost as xgb
from datetime import datetime, timezone

DEFAULT_MODEL_PATH = "/opt/dfi2/ml/models/xgb_20260305_173500.json"
BATCH_SIZE = 2_000_000
TMP = "/tmp/norm_rescore"
STATUS_FILE = f"{TMP}/status.json"

MODEL_FEATURES = [
    "dst_port", "ip_proto", "app_proto",
    "pkts_fwd", "pkts_rev", "bytes_fwd", "bytes_rev",
    "bytes_per_pkt_fwd", "bytes_per_pkt_rev", "pkt_ratio", "byte_ratio",
    "duration_ms", "rtt_ms", "iat_fwd_mean_ms", "iat_fwd_std_ms",
    "think_time_mean_ms", "think_time_std_ms", "iat_to_rtt",
    "pps", "bps", "payload_rtt_ratio",
    "n_events", "fwd_size_mean", "fwd_size_std", "fwd_size_min", "fwd_size_max",
    "rev_size_mean", "rev_size_std", "rev_size_max",
    "hist_tiny", "hist_small", "hist_medium", "hist_large", "hist_full", "frac_full",
    "syn_count", "fin_count", "rst_count", "psh_count", "ack_only_count",
    "conn_state", "rst_frac", "syn_to_data", "psh_burst_max", "retransmit_est", "window_size_init",
    "entropy_first", "entropy_fwd_mean", "entropy_rev_mean",
    "printable_frac", "null_frac", "byte_std", "high_entropy_frac", "payload_len_first",
    "ja3_freq", "tls_version", "tls_cipher_count", "tls_ext_count", "tls_has_sni",
    "hassh_freq", "ssh_kex_count",
    "http_method", "http_uri_len", "http_header_count", "http_ua_freq", "http_has_body", "http_status",
    "dns_qtype", "dns_qname_len",
    "src_flow_count", "src_unique_ports", "src_unique_protos", "src_unique_dsts",
    "src_span_min", "src_avg_pps",
]

TSV_FEAT_COLS = [
    "dst_port", "ip_proto", "app_proto",
    "pkts_fwd", "pkts_rev", "bytes_fwd", "bytes_rev",
    "bytes_per_pkt_fwd", "bytes_per_pkt_rev", "pkt_ratio", "byte_ratio",
    "duration_ms", "rtt_ms", "iat_fwd_mean_ms", "iat_fwd_std_ms",
    "think_time_mean_ms", "think_time_std_ms", "iat_to_rtt",
    "pps", "bps", "payload_rtt_ratio",
    "n_events", "fwd_size_mean", "fwd_size_std", "fwd_size_min", "fwd_size_max",
    "rev_size_mean", "rev_size_std", "rev_size_max",
    "hist_tiny", "hist_small", "hist_medium", "hist_large", "hist_full", "frac_full",
    "syn_count", "fin_count", "rst_count", "psh_count", "ack_only_count",
    "conn_state", "rst_frac", "syn_to_data", "psh_burst_max", "retransmit_est", "window_size_init",
    "entropy_first", "entropy_fwd_mean", "entropy_rev_mean",
    "printable_frac", "null_frac", "byte_std", "high_entropy_frac", "payload_len_first",
]

FEATURES_SQL = """
    f.flow_id, toString(f.src_ip) AS src_ip, toString(f.dst_ip) AS dst_ip,
    f.dst_port, toString(f.first_ts) AS first_ts,
    f.dst_port AS feat_dst_port,
    f.ip_proto, f.app_proto,
    f.pkts_fwd, f.pkts_rev, f.bytes_fwd, f.bytes_rev,
    toFloat64(f.bytes_fwd) / greatest(f.pkts_fwd, 1) AS bytes_per_pkt_fwd,
    if(f.pkts_rev > 0, toFloat64(f.bytes_rev) / f.pkts_rev, 0) AS bytes_per_pkt_rev,
    toFloat64(f.pkts_fwd) / greatest(f.pkts_rev, 1) AS pkt_ratio,
    toFloat64(f.bytes_fwd) / greatest(f.bytes_rev, 1) AS byte_ratio,
    f.duration_ms,
    ifNull(f.rtt_ms, 0) AS rtt_ms,
    ifNull(f.iat_fwd_mean_ms, 0) AS iat_fwd_mean_ms,
    ifNull(f.iat_fwd_std_ms, 0) AS iat_fwd_std_ms,
    ifNull(f.think_time_mean_ms, 0) AS think_time_mean_ms,
    ifNull(f.think_time_std_ms, 0) AS think_time_std_ms,
    ifNull(f.iat_to_rtt, 0) AS iat_to_rtt,
    f.pps, f.bps,
    ifNull(f.payload_rtt_ratio, 0) AS payload_rtt_ratio,
    f.n_events,
    ifNull(f.fwd_size_mean, 0) AS fwd_size_mean,
    ifNull(f.fwd_size_std, 0) AS fwd_size_std,
    f.fwd_size_min, f.fwd_size_max,
    ifNull(f.rev_size_mean, 0) AS rev_size_mean,
    ifNull(f.rev_size_std, 0) AS rev_size_std,
    f.rev_size_max,
    f.hist_tiny, f.hist_small, f.hist_medium, f.hist_large, f.hist_full, f.frac_full,
    f.syn_count, f.fin_count, f.rst_count, f.psh_count, f.ack_only_count,
    f.conn_state,
    ifNull(f.rst_frac, 0) AS rst_frac,
    f.syn_to_data, f.psh_burst_max, f.retransmit_est, f.window_size_init,
    ifNull(f.entropy_first, 0) AS entropy_first,
    ifNull(f.entropy_fwd_mean, 0) AS entropy_fwd_mean,
    ifNull(f.entropy_rev_mean, 0) AS entropy_rev_mean,
    ifNull(f.printable_frac, 0) AS printable_frac,
    ifNull(f.null_frac, 0) AS null_frac,
    ifNull(f.byte_std, 0) AS byte_std,
    ifNull(f.high_entropy_frac, 0) AS high_entropy_frac,
    f.payload_len_first
"""

PRED_INSERT_COLS = "flow_id, src_ip, dst_ip, dst_port, flow_first_ts, model_name, model_version, label, confidence, class_probs, scored_at"


def ch(query, output_file=None, fmt="TabSeparated", input_file=None):
    cmd = ["clickhouse-client", "--query", query]
    if fmt != "TabSeparated":
        cmd.extend(["--format", fmt])
    stdin_f = open(input_file, "rb") if input_file else None
    stdout_f = open(output_file, "wb") if output_file else subprocess.PIPE
    try:
        r = subprocess.run(cmd, stdin=stdin_f, stdout=stdout_f,
                           stderr=subprocess.PIPE, check=True)
        if not output_file:
            return r.stdout.decode().strip()
    finally:
        if stdin_f:
            stdin_f.close()
        if output_file and stdout_f:
            stdout_f.close()


def write_status(**kwargs):
    """Write/update status JSON file."""
    status = {}
    if os.path.exists(STATUS_FILE):
        try:
            with open(STATUS_FILE) as f:
                status = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    status.update(kwargs)
    with open(STATUS_FILE, "w") as f:
        json.dump(status, f)


def parse_args():
    p = argparse.ArgumentParser(description="Score flows by label with XGB model")
    p.add_argument("--model-path", default=DEFAULT_MODEL_PATH, help="Path to XGB .json model")
    p.add_argument("--model-name", default="xgb_v7", help="model_name written to model_predictions")
    p.add_argument("--model-version", default="rescore", help="model_version written to model_predictions")
    p.add_argument("--labels", default="5", help="Comma-separated label IDs to score, e.g. '0,5' or '1,2,3'")
    p.add_argument("--skip-scored", action=argparse.BooleanOptionalAction, default=True,
                   help="Skip already-scored flows (default: true)")
    return p.parse_args()


def build_count_query(labels_csv, model_name, skip_scored):
    """Build the count query for matching flows."""
    if skip_scored:
        return f"""
            SELECT count() FROM (
                SELECT DISTINCT l.flow_id FROM dfi.labels l
                LEFT ANTI JOIN dfi.model_predictions p
                    ON p.flow_id = l.flow_id AND p.model_name = '{model_name}'
                WHERE l.label IN ({labels_csv})
            )
        """
    else:
        return f"""
            SELECT count(DISTINCT flow_id) FROM dfi.labels
            WHERE label IN ({labels_csv})
        """


def build_batch_insert(labels_csv, model_name, skip_scored, limit):
    """Build the batch INSERT INTO _rescore_batch query."""
    if skip_scored:
        return f"""
            INSERT INTO dfi._rescore_batch
            SELECT DISTINCT l.flow_id FROM dfi.labels l
            LEFT ANTI JOIN dfi.model_predictions p
                ON p.flow_id = l.flow_id AND p.model_name = '{model_name}'
            WHERE l.label IN ({labels_csv})
            LIMIT {limit}
        """
    else:
        return f"""
            INSERT INTO dfi._rescore_batch
            SELECT DISTINCT flow_id FROM dfi.labels
            WHERE label IN ({labels_csv})
            LIMIT {limit}
        """


def main():
    args = parse_args()
    model_path = args.model_path
    model_name = args.model_name
    model_version = args.model_version
    labels_list = [int(x.strip()) for x in args.labels.split(",")]
    labels_csv = ",".join(str(x) for x in labels_list)
    skip_scored = args.skip_scored

    config = {
        "model_path": model_path,
        "model_name": model_name,
        "model_version": model_version,
        "labels": labels_list,
        "skip_scored": skip_scored,
    }

    os.makedirs(TMP, exist_ok=True)
    now_iso = datetime.now(timezone.utc).isoformat()
    write_status(status="running", started_at=now_iso, scored=0, batch=0,
                 attack_count=0, norm_count=0, error=None, config=config)

    try:
        # Load model
        booster = xgb.Booster()
        booster.load_model(model_path)
        print(f"Model loaded: {len(booster.feature_names)} features from {model_path}")

        # Get total
        total = int(ch(build_count_query(labels_csv, model_name, skip_scored)))
        print(f"Total {'unscored' if skip_scored else 'matching'}: {total:,}")
        write_status(total=total)

        if total == 0:
            write_status(status="completed", finished_at=datetime.now(timezone.utc).isoformat(),
                         last_run_results={"total": 0, "attack": 0, "norm": 0, "elapsed_sec": 0, "rate": 0})
            return

        t_start = time.time()
        scored_total = 0
        attack_total = 0
        norm_total = 0
        batch_num = 0

        while True:
            batch_num += 1
            write_status(batch=batch_num)

            # Create temp table for batch
            ch("DROP TABLE IF EXISTS dfi._rescore_batch")
            ch("CREATE TABLE dfi._rescore_batch (flow_id String) ENGINE = MergeTree() ORDER BY flow_id")
            ch(build_batch_insert(labels_csv, model_name, skip_scored, BATCH_SIZE))
            batch_n = int(ch("SELECT count() FROM dfi._rescore_batch"))
            print(f"\nBatch {batch_num}: {batch_n:,} IDs")

            if batch_n == 0:
                break

            # Fetch features
            feats_f = f"{TMP}/feats.tsv"
            t0 = time.time()
            ch(f"""
                SELECT {FEATURES_SQL}
                FROM dfi.flows f
                ANY INNER JOIN dfi._rescore_batch b ON b.flow_id = f.flow_id
            """, feats_f, fmt="TabSeparatedWithNames")

            # Load with pyarrow
            tbl = pcsv.read_csv(feats_f, parse_options=pcsv.ParseOptions(delimiter="\t"))
            df = tbl.to_pandas()
            print(f"  Fetched {len(df):,} rows ({time.time()-t0:.1f}s)")

            if len(df) == 0:
                break

            # Build feature matrix
            feat_arr = df[TSV_FEAT_COLS].values.astype(np.float32)
            zeros = np.zeros((feat_arr.shape[0], 21), dtype=np.float32)
            full_feat = np.hstack([feat_arr, zeros])

            # Predict
            t0 = time.time()
            dmat = xgb.DMatrix(full_feat, feature_names=MODEL_FEATURES, nthread=80)
            probs = booster.predict(dmat)
            labels = (probs >= 0.5).astype(np.uint8)
            confs = np.where(labels == 1, probs, 1.0 - probs).astype(np.float32)
            n_attack = int(labels.sum())
            n_norm = len(labels) - n_attack
            print(f"  Predicted ({time.time()-t0:.1f}s): ATTACK={n_attack:,} NORM={n_norm:,}")

            # Write predictions TSV
            preds_f = f"{TMP}/preds.tsv"
            scored_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            p_norms = 1.0 - probs
            out_df = pd.DataFrame({
                "flow_id": df["flow_id"].values,
                "src_ip": df["src_ip"].values,
                "dst_ip": df["dst_ip"].values,
                "dst_port": df["dst_port"].values,
                "first_ts": df["first_ts"].values,
                "model_name": model_name,
                "model_version": model_version,
                "label": labels,
            })
            out_df["confidence"] = [f"{c:.6f}" for c in confs]
            out_df["class_probs"] = [f"[{pn:.6f},{pa:.6f}]" for pn, pa in zip(p_norms, probs)]
            out_df["scored_at"] = scored_at
            out_df.to_csv(preds_f, sep="\t", index=False, header=False)

            # Insert
            ch(f"INSERT INTO dfi.model_predictions_buffer ({PRED_INSERT_COLS}) FORMAT TabSeparated",
               input_file=preds_f)

            scored_total += len(df)
            attack_total += n_attack
            norm_total += n_norm
            elapsed = time.time() - t_start
            rate = scored_total / elapsed if elapsed > 0 else 0

            write_status(
                scored=scored_total, attack_count=attack_total, norm_count=norm_total,
                elapsed_sec=round(elapsed, 1), rate=round(rate, 0),
            )
            print(f"  Progress: {scored_total:,}/{total:,} ({scored_total*100/total:.1f}%) rate={rate:,.0f}/s")

            del df, feat_arr, full_feat, dmat, probs, labels, confs, out_df, p_norms
            gc.collect()

        ch("DROP TABLE IF EXISTS dfi._rescore_batch")
        elapsed = time.time() - t_start
        results = {
            "total": scored_total,
            "attack": attack_total,
            "norm": norm_total,
            "elapsed_sec": round(elapsed, 1),
            "rate": round(scored_total / elapsed, 0) if elapsed > 0 else 0,
        }
        write_status(
            status="completed",
            scored=scored_total,
            finished_at=datetime.now(timezone.utc).isoformat(),
            elapsed_sec=round(elapsed, 1),
            rate=round(scored_total / elapsed, 0) if elapsed > 0 else 0,
            last_run_results=results,
        )
        print(f"\nDONE: {scored_total:,} scored in {elapsed:.0f}s ({scored_total/elapsed:,.0f}/s)")

    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        write_status(
            status="failed",
            error=str(exc),
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        try:
            ch("DROP TABLE IF EXISTS dfi._rescore_batch")
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
