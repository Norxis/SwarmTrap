#!/usr/bin/env python3
"""Benchmark 5 approaches for scoring unscored label-5 flows with XGB v6.

Run on PV1. Uses temp CH table for 1M flow_ids.
"""
import os, sys, time, subprocess, gc
import numpy as np
import pandas as pd
import xgboost as xgb
from datetime import datetime, timezone

MODEL_PATH = "/opt/dfi2/ml/models/xgb_20260302_154900.json"
BENCH_N = 1_000_000
TMP = "/tmp/bench_score"

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

# Use ifNull to replace NULLs with 0 in SQL, avoiding \N in TSV
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

# Use ANY INNER JOIN to avoid row multiplication from flows duplicates
FETCH_QUERY = f"""
    SELECT {FEATURES_SQL}
    FROM dfi.flows f
    ANY INNER JOIN dfi._bench_fids bf ON bf.flow_id = f.flow_id
"""

PRED_INSERT_COLS = ["flow_id", "src_ip", "dst_ip", "dst_port", "flow_first_ts",
                    "model_name", "model_version", "label", "confidence", "class_probs", "scored_at"]


def ch_cmd(query, output_file=None, fmt="TabSeparated", input_file=None):
    cmd = ["clickhouse-client", "--query", query]
    if fmt != "TabSeparated":
        cmd.extend(["--format", fmt])
    kwargs = {"check": True}
    if input_file:
        kwargs["stdin"] = open(input_file, "rb")
    if output_file:
        kwargs["stdout"] = open(output_file, "wb")
        subprocess.run(cmd, **kwargs)
        if "stdin" in kwargs: kwargs["stdin"].close()
        if "stdout" in kwargs: kwargs["stdout"].close()
    else:
        kwargs["capture_output"] = True
        r = subprocess.run(cmd, **kwargs)
        if "stdin" in kwargs: kwargs["stdin"].close()
        return r.stdout.decode().strip()


def write_preds_tsv(output_file, flow_ids, src_ips, dst_ips, dst_ports, first_tss,
                    labels, confidences, probs):
    scored_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    p_norms = 1.0 - probs
    lines = []
    for i in range(len(flow_ids)):
        lines.append(f"{flow_ids[i]}\t{src_ips[i]}\t{dst_ips[i]}\t{dst_ports[i]}\t{first_tss[i]}\t"
                     f"xgb_v6\txgb_v6_norm_rescore\t{labels[i]}\t{confidences[i]:.6f}\t"
                     f"[{p_norms[i]:.6f},{probs[i]:.6f}]\t{scored_at}\n")
    with open(output_file, "w") as f:
        f.writelines(lines)


def write_preds_tsv_fast(output_file, flow_ids, src_ips, dst_ips, dst_ports, first_tss,
                         labels, confidences, probs):
    """Vectorized TSV write using numpy/pandas."""
    scored_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    p_norms = 1.0 - probs
    # Build DataFrame for fast CSV export
    df = pd.DataFrame({
        "flow_id": flow_ids, "src_ip": src_ips, "dst_ip": dst_ips,
        "dst_port": dst_ports, "first_ts": first_tss,
        "model_name": "xgb_v6", "model_version": "xgb_v6_norm_rescore",
        "label": labels,
    })
    # Format floats and arrays as strings
    df["confidence"] = [f"{c:.6f}" for c in confidences]
    df["class_probs"] = [f"[{pn:.6f},{pa:.6f}]" for pn, pa in zip(p_norms, probs)]
    df["scored_at"] = scored_at
    df.to_csv(output_file, sep="\t", index=False, header=False)


def setup():
    os.makedirs(TMP, exist_ok=True)
    ch_cmd("DROP TABLE IF EXISTS dfi._bench_fids")
    ch_cmd("CREATE TABLE dfi._bench_fids (flow_id String) ENGINE = MergeTree() ORDER BY flow_id")

    print(f"Populating {BENCH_N:,} DISTINCT unscored label-5 flow_ids...")
    t0 = time.time()
    ch_cmd(f"""
        INSERT INTO dfi._bench_fids
        SELECT DISTINCT l.flow_id FROM dfi.labels l
        LEFT ANTI JOIN dfi.model_predictions p
            ON p.flow_id = l.flow_id AND p.model_name = 'xgb_v6'
        WHERE l.label = 5
        LIMIT {BENCH_N}
    """)
    n = ch_cmd("SELECT count() FROM dfi._bench_fids")
    print(f"  {n} flow_ids in {time.time()-t0:.1f}s")

    ch_cmd("DROP TABLE IF EXISTS dfi._bench_preds")
    ch_cmd("CREATE TABLE dfi._bench_preds AS dfi.model_predictions ENGINE = MergeTree() ORDER BY (flow_id, model_name, scored_at)")


def predict_xgb(booster, feat_matrix):
    dmat = xgb.DMatrix(feat_matrix, feature_names=MODEL_FEATURES, nthread=80)
    probs = booster.predict(dmat)
    labels = (probs >= 0.5).astype(np.uint8)
    confs = np.where(labels == 1, probs, 1.0 - probs).astype(np.float32)
    return labels, confs, probs


def build_feature_matrix(df):
    """Extract 54 flow features from df, append 21 zeros, return float32 array."""
    feat = df[TSV_FEAT_COLS].values.astype(np.float32)
    zeros = np.zeros((feat.shape[0], 21), dtype=np.float32)
    return np.hstack([feat, zeros])


# ─── APPROACH A: CH TSV → pyarrow → XGB → CH TSV INSERT ───
def bench_a(booster):
    print("\n=== A: CH-TSV → pyarrow → XGB → CH-INSERT ===")
    t = {}; feats_f = f"{TMP}/a.tsv"; preds_f = f"{TMP}/a_pred.tsv"

    t0 = time.time()
    ch_cmd(FETCH_QUERY, feats_f, fmt="TabSeparatedWithNames")
    t["fetch"] = time.time() - t0

    t0 = time.time()
    import pyarrow.csv as pcsv
    tbl = pcsv.read_csv(feats_f, parse_options=pcsv.ParseOptions(delimiter="\t"))
    df = tbl.to_pandas()
    t["load"] = time.time() - t0
    print(f"  Fetch={t['fetch']:.2f}s Load={t['load']:.2f}s rows={len(df)}")

    t0 = time.time()
    labels, confs, probs = predict_xgb(booster, build_feature_matrix(df))
    t["predict"] = time.time() - t0

    t0 = time.time()
    write_preds_tsv_fast(preds_f, df["flow_id"].values, df["src_ip"].values,
                         df["dst_ip"].values, df["dst_port"].values,
                         df["first_ts"].values, labels, confs, probs)
    t["write"] = time.time() - t0

    t0 = time.time()
    ch_cmd(f"INSERT INTO dfi._bench_preds ({','.join(PRED_INSERT_COLS)}) FORMAT TabSeparated",
           input_file=preds_f)
    t["insert"] = time.time() - t0

    t["total"] = sum(t.values())
    return t


# ─── APPROACH B: CH TSV → pandas → XGB → CH TSV INSERT ───
def bench_b(booster):
    print("\n=== B: CH-TSV → pandas → XGB → CH-INSERT ===")
    t = {}; feats_f = f"{TMP}/b.tsv"; preds_f = f"{TMP}/b_pred.tsv"

    t0 = time.time()
    ch_cmd(FETCH_QUERY, feats_f, fmt="TabSeparatedWithNames")
    t["fetch"] = time.time() - t0

    t0 = time.time()
    df = pd.read_csv(feats_f, sep="\t")
    t["load"] = time.time() - t0
    print(f"  Fetch={t['fetch']:.2f}s Load={t['load']:.2f}s rows={len(df)}")

    t0 = time.time()
    labels, confs, probs = predict_xgb(booster, build_feature_matrix(df))
    t["predict"] = time.time() - t0

    t0 = time.time()
    write_preds_tsv_fast(preds_f, df["flow_id"].values, df["src_ip"].values,
                         df["dst_ip"].values, df["dst_port"].values,
                         df["first_ts"].values, labels, confs, probs)
    t["write"] = time.time() - t0

    t0 = time.time()
    ch_cmd(f"INSERT INTO dfi._bench_preds ({','.join(PRED_INSERT_COLS)}) FORMAT TabSeparated",
           input_file=preds_f)
    t["insert"] = time.time() - t0

    t["total"] = sum(t.values())
    return t


# ─── APPROACH C: clickhouse-driver ───
def bench_c(booster):
    print("\n=== C: clickhouse-driver (Python) ===")
    t = {}
    from clickhouse_driver import Client as CHClient
    ch = CHClient(host="localhost", settings={"max_block_size": 500_000})

    t0 = time.time()
    rows, cols = ch.execute(FETCH_QUERY.replace("\n", " "), with_column_types=True)
    t["fetch"] = time.time() - t0

    t0 = time.time()
    col_names = [c[0] for c in cols]
    df = pd.DataFrame(rows, columns=col_names)
    # Convert IPv4 objects to strings
    df["src_ip"] = df["src_ip"].astype(str)
    df["dst_ip"] = df["dst_ip"].astype(str)
    df["first_ts"] = df["first_ts"].astype(str)
    # Replace None/NaN with 0 in feature cols
    df[TSV_FEAT_COLS] = df[TSV_FEAT_COLS].fillna(0)
    t["load"] = time.time() - t0
    print(f"  Fetch={t['fetch']:.2f}s Load={t['load']:.2f}s rows={len(df)}")

    t0 = time.time()
    labels, confs, probs = predict_xgb(booster, build_feature_matrix(df))
    t["predict"] = time.time() - t0

    # Write to TSV + CH INSERT (same as A/B — driver INSERT is too slow for comparison)
    preds_f = f"{TMP}/c_pred.tsv"
    t0 = time.time()
    write_preds_tsv_fast(preds_f, df["flow_id"].values, df["src_ip"].values,
                         df["dst_ip"].values, df["dst_port"].values,
                         df["first_ts"].values, labels, confs, probs)
    t["write"] = time.time() - t0

    t0 = time.time()
    ch_cmd(f"INSERT INTO dfi._bench_preds ({','.join(PRED_INSERT_COLS)}) FORMAT TabSeparated",
           input_file=preds_f)
    t["insert"] = time.time() - t0

    t["total"] = sum(t.values())
    return t


# ─── APPROACH D: CH Arrow → pyarrow → XGB → CH INSERT ───
def bench_d(booster):
    print("\n=== D: CH-Arrow → pyarrow → XGB → CH-INSERT ===")
    t = {}
    import pyarrow.ipc as ipc
    feats_f = f"{TMP}/d.arrow"; preds_f = f"{TMP}/d_pred.tsv"

    t0 = time.time()
    ch_cmd(FETCH_QUERY, feats_f, fmt="ArrowStream")
    t["fetch"] = time.time() - t0

    t0 = time.time()
    with open(feats_f, "rb") as fh:
        tbl = ipc.open_stream(fh).read_all()
    df = tbl.to_pandas()
    # Arrow may keep IP as bytes — convert
    for c in ["src_ip", "dst_ip", "first_ts"]:
        if df[c].dtype == object:
            df[c] = df[c].astype(str)
    t["load"] = time.time() - t0
    print(f"  Fetch={t['fetch']:.2f}s Load={t['load']:.2f}s rows={len(df)}")

    t0 = time.time()
    labels, confs, probs = predict_xgb(booster, build_feature_matrix(df))
    t["predict"] = time.time() - t0

    t0 = time.time()
    write_preds_tsv_fast(preds_f, df["flow_id"].values, df["src_ip"].values,
                         df["dst_ip"].values, df["dst_port"].values,
                         df["first_ts"].values, labels, confs, probs)
    t["write"] = time.time() - t0

    t0 = time.time()
    ch_cmd(f"INSERT INTO dfi._bench_preds ({','.join(PRED_INSERT_COLS)}) FORMAT TabSeparated",
           input_file=preds_f)
    t["insert"] = time.time() - t0

    t["total"] = sum(t.values())
    return t


# ─── APPROACH E: CH TSV → numpy direct → XGB → CH INSERT ───
def bench_e(booster):
    print("\n=== E: CH-TSV → numpy → XGB → CH-INSERT ===")
    t = {}; feats_f = f"{TMP}/e.tsv"; preds_f = f"{TMP}/e_pred.tsv"

    t0 = time.time()
    ch_cmd(FETCH_QUERY, feats_f, fmt="TabSeparatedWithNames")
    t["fetch"] = time.time() - t0

    t0 = time.time()
    # Use pandas just for meta, numpy for features
    df = pd.read_csv(feats_f, sep="\t")
    feat_arr = df[TSV_FEAT_COLS].values.astype(np.float32)
    zeros = np.zeros((feat_arr.shape[0], 21), dtype=np.float32)
    feat_arr = np.hstack([feat_arr, zeros])
    t["load"] = time.time() - t0
    print(f"  Fetch={t['fetch']:.2f}s Load={t['load']:.2f}s rows={len(df)}")

    t0 = time.time()
    dmat = xgb.DMatrix(feat_arr, feature_names=MODEL_FEATURES, nthread=80)
    probs = dmat  # just to hold ref
    labels, confs, probs = predict_xgb(booster, feat_arr)
    t["predict"] = time.time() - t0

    t0 = time.time()
    write_preds_tsv_fast(preds_f, df["flow_id"].values, df["src_ip"].values,
                         df["dst_ip"].values, df["dst_port"].values,
                         df["first_ts"].values, labels, confs, probs)
    t["write"] = time.time() - t0

    t0 = time.time()
    ch_cmd(f"INSERT INTO dfi._bench_preds ({','.join(PRED_INSERT_COLS)}) FORMAT TabSeparated",
           input_file=preds_f)
    t["insert"] = time.time() - t0

    t["total"] = sum(t.values())
    return t


def main():
    print("=" * 70)
    print(f"XGB v6 Scoring Benchmark — {BENCH_N:,} unscored label-5 flows")
    print("=" * 70)

    setup()
    booster = xgb.Booster()
    booster.load_model(MODEL_PATH)
    print(f"Model: {len(booster.feature_names)} features\n")

    results = {}
    for name, fn in [("A (pyarrow)", bench_a), ("B (pandas)", bench_b),
                     ("C (driver)", bench_c), ("D (arrow)", bench_d), ("E (numpy)", bench_e)]:
        ch_cmd("TRUNCATE TABLE dfi._bench_preds")
        gc.collect()
        try:
            results[name] = fn(booster)
        except Exception as e:
            print(f"  FAILED: {e}")
            import traceback; traceback.print_exc()
            results[name] = None
        gc.collect()

    print("\n" + "=" * 90)
    print(f"{'Approach':<16} | {'Fetch':>8} | {'Load':>8} | {'Predict':>8} | {'Write':>8} | {'Insert':>8} | {'TOTAL':>8}")
    print("-" * 90)
    for name, t in results.items():
        if t is None:
            print(f"{name:<16} | FAILED")
        else:
            print(f"{name:<16} | {t['fetch']:>7.2f}s | {t['load']:>7.2f}s | {t['predict']:>7.2f}s "
                  f"| {t['write']:>7.2f}s | {t['insert']:>7.2f}s | {t['total']:>7.2f}s")

    ch_cmd("DROP TABLE IF EXISTS dfi._bench_preds")
    ch_cmd("DROP TABLE IF EXISTS dfi._bench_fids")
    print("\nDone. Winner gets used for full 8.5M run.")


if __name__ == "__main__":
    main()
