"""Standalone CSV export per spec Module 6.

Generates XGB and CNN format CSVs from the SQLite buffer without ClickHouse.
"""
from __future__ import annotations

import argparse
import csv
import sqlite3
from pathlib import Path

# XGB column order per DFI_XGB_v1_Spec
_XGB_COLS = [
    "flow_id", "session_key",
    "dst_port", "ip_proto", "app_proto",
    "pkts_fwd", "pkts_rev", "bytes_fwd", "bytes_rev",
    "bytes_per_pkt_fwd", "bytes_per_pkt_rev", "pkt_ratio", "byte_ratio",
    "rtt_ms", "duration_ms", "iat_fwd_mean_ms", "iat_fwd_std_ms",
    "think_time_mean_ms", "think_time_std_ms", "iat_to_rtt", "pps", "bps", "payload_rtt_ratio",
    "n_events", "fwd_size_mean", "fwd_size_std", "fwd_size_min", "fwd_size_max",
    "rev_size_mean", "rev_size_std", "rev_size_max",
    "hist_tiny", "hist_small", "hist_medium", "hist_large", "hist_full", "frac_full",
    "syn_count", "fin_count", "rst_count", "psh_count", "ack_only_count", "conn_state",
    "rst_frac", "syn_to_data", "psh_burst_max", "retransmit_est", "window_size_init",
    "entropy_first", "entropy_fwd_mean", "entropy_rev_mean",
    "printable_frac", "null_frac", "byte_std", "high_entropy_frac", "payload_len_first",
]

# CNN channels per spec
_CNN_CHANNELS = [
    "size_dir_token", "flag_token", "iat_log_ms_bin", "iat_rtt_bin", "entropy_bin",
]


def export_xgb(db_path: str, output: str) -> int:
    """Export XGB features CSV. Returns row count."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM pcap_flows ORDER BY first_ts").fetchall()
    conn.close()

    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_XGB_COLS, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            row = {k: r[k] for k in r.keys()}
            # None → empty string for CSV
            writer.writerow({k: ("" if row.get(k) is None else row.get(k, "")) for k in _XGB_COLS})

    return len(rows)


def export_cnn(db_path: str, output: str) -> int:
    """Export CNN tokens CSV (pivoted: 5 channels x 128 positions). Returns flow count."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # Get all flow IDs
    flow_ids = [r[0] for r in conn.execute(
        "SELECT DISTINCT flow_id FROM pcap_flows ORDER BY first_ts"
    ).fetchall()]

    # Get flow metadata
    flows_meta = {}
    for r in conn.execute("SELECT flow_id, session_key, dst_port, ip_proto, app_proto, "
                          "pkts_fwd, pkts_rev, bytes_fwd, bytes_rev, rtt_ms, n_events, "
                          "entropy_first, entropy_fwd_mean, entropy_rev_mean, "
                          "printable_frac, null_frac, byte_std, high_entropy_frac, "
                          "payload_len_first FROM pcap_flows").fetchall():
        flows_meta[r["flow_id"]] = dict(r)

    # Build header: flow_id, session_key, 5 channels x 128 positions, then metadata
    header = ["flow_id", "session_key"]
    for ch in ["size_dir", "tcp_flags", "iat_log_ms", "iat_rtt_bin", "entropy_bin"]:
        for i in range(1, 129):
            header.append(f"{ch}_seq_{i}")
    header.extend([
        "dst_port", "ip_proto", "app_proto",
        "pkts_fwd", "pkts_rev", "bytes_fwd", "bytes_rev",
        "rtt_ms", "n_events",
        "entropy_first", "entropy_fwd_mean", "entropy_rev_mean",
        "printable_frac", "null_frac", "byte_std", "high_entropy_frac", "payload_len_first",
    ])

    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)

        for fid in flow_ids:
            pkts = conn.execute(
                "SELECT * FROM pcap_packets WHERE flow_id=? ORDER BY seq_idx",
                (fid,)
            ).fetchall()

            # Build channel sequences (pad to 128)
            channels: dict[str, list[int]] = {ch: [] for ch in _CNN_CHANNELS}
            for p in pkts[:128]:
                for ch in _CNN_CHANNELS:
                    channels[ch].append(p[ch])
            # Pad
            for ch in _CNN_CHANNELS:
                while len(channels[ch]) < 128:
                    channels[ch].append(0)

            meta = flows_meta.get(fid, {})
            row = [fid, meta.get("session_key", "")]
            for ch in _CNN_CHANNELS:
                row.extend(channels[ch])
            row.extend([
                meta.get("dst_port", ""), meta.get("ip_proto", ""), meta.get("app_proto", ""),
                meta.get("pkts_fwd", ""), meta.get("pkts_rev", ""),
                meta.get("bytes_fwd", ""), meta.get("bytes_rev", ""),
                "" if meta.get("rtt_ms") is None else meta["rtt_ms"],
                meta.get("n_events", ""),
                "" if meta.get("entropy_first") is None else meta["entropy_first"],
                "" if meta.get("entropy_fwd_mean") is None else meta["entropy_fwd_mean"],
                "" if meta.get("entropy_rev_mean") is None else meta["entropy_rev_mean"],
                "" if meta.get("printable_frac") is None else meta["printable_frac"],
                "" if meta.get("null_frac") is None else meta["null_frac"],
                "" if meta.get("byte_std") is None else meta["byte_std"],
                "" if meta.get("high_entropy_frac") is None else meta["high_entropy_frac"],
                meta.get("payload_len_first", ""),
            ])
            writer.writerow(row)

    conn.close()
    return len(flow_ids)


# ── Evidence bit constants (inline fallback for standalone execution) ──
try:
    from .evidence_bits import (  # type: ignore[import]
        AUTH_FAILURE, AUTH_SUCCESS, PROCESS_CREATE, SERVICE_INSTALL,
        SUSPICIOUS_COMMAND, FILE_DOWNLOAD, PRIVILEGE_ESCALATION,
        LATERAL_MOVEMENT, OUTBOUND_C2, CREDENTIAL_THEFT, PERSISTENCE_MECHANISM,
        DATA_EXFILTRATION, TOOL_DEPLOYMENT, EVASION_ATTEMPT, MEMORY_ONLY_TOOL,
        DNS_TUNNELING,
    )
except ImportError:
    AUTH_FAILURE = 0x0001; AUTH_SUCCESS = 0x0002; PROCESS_CREATE = 0x0004
    SERVICE_INSTALL = 0x0008; SUSPICIOUS_COMMAND = 0x0010; FILE_DOWNLOAD = 0x0020
    PRIVILEGE_ESCALATION = 0x0040; LATERAL_MOVEMENT = 0x0080; OUTBOUND_C2 = 0x0100
    CREDENTIAL_THEFT = 0x0200; PERSISTENCE_MECHANISM = 0x0400; DATA_EXFILTRATION = 0x0800
    TOOL_DEPLOYMENT = 0x1000; EVASION_ATTEMPT = 0x2000; MEMORY_ONLY_TOOL = 0x4000
    DNS_TUNNELING = 0x8000

_COMPROMISE_BITS = (
    PRIVILEGE_ESCALATION | SERVICE_INSTALL | TOOL_DEPLOYMENT | EVASION_ATTEMPT |
    CREDENTIAL_THEFT | OUTBOUND_C2 | DATA_EXFILTRATION | MEMORY_ONLY_TOOL |
    DNS_TUNNELING | LATERAL_MOVEMENT | PERSISTENCE_MECHANISM
)
_EXPLOIT_BITS    = AUTH_SUCCESS | PROCESS_CREATE | SUSPICIOUS_COMMAND | FILE_DOWNLOAD
_BRUTEFORCE_BITS = AUTH_FAILURE


def _derive_label(evidence_bits: int) -> tuple:
    """Map accumulated evidence_bits to DFI2 kill-chain label (2=BRUTEFORCE, 3=EXPLOIT, 4=COMPROMISE)."""
    if evidence_bits & _COMPROMISE_BITS:
        return 4, "COMPROMISE"
    if evidence_bits & _EXPLOIT_BITS:
        return 3, "EXPLOIT"
    if evidence_bits & _BRUTEFORCE_BITS:
        return 2, "BRUTEFORCE"
    return None, "UNLABELED"


def _iso_to_epoch(ts: str) -> float:
    """Parse ISO8601 UTC timestamp string to Unix epoch float. Returns 0.0 on failure."""
    from datetime import datetime
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError, TypeError):
        return 0.0


def export_labeled(db_path: str, output: str, evidence_window_s: float = 120.0) -> tuple:
    """Export labeled training CSV — correlates network flows with host-level evidence.

    WinHunt's unique advantage: runs inside Windows so it can correlate every
    network flow with Windows Event Log evidence (auth success/failure, process
    creation, service installs, privilege escalation) via the logon_map chain.
    This produces GROUND TRUTH kill-chain labels — not inferred, not threat-intel
    based, but confirmed by the OS itself.

    Evidence correlation: for each flow, aggregates evidence_bits from the events
    table WHERE source_ip = flow.src_ip AND ts WITHIN ±evidence_window_s of the flow.

    Label scheme (DFI2-compatible):
        2 = BRUTEFORCE  (AUTH_FAILURE events only)
        3 = EXPLOIT     (AUTH_SUCCESS, PROCESS_CREATE, SUSPICIOUS_COMMAND, FILE_DOWNLOAD)
        4 = COMPROMISE  (PRIVILEGE_ESCALATION, SERVICE_INSTALL, TOOL_DEPLOYMENT,
                         EVASION_ATTEMPT, OUTBOUND_C2, CREDENTIAL_THEFT, etc.)

    Output columns:
        Identity  (7):  flow_id, src_ip, dst_ip, src_port, dst_port, first_ts, last_ts
        Labels    (5):  evidence_bits, label, label_name, auth_failure_count, auth_success_count
        F1-F6    (54):  XGB features (stored) + 4 derived F2 (bytes_per_pkt_*, pkt_ratio, byte_ratio)
        F7        (7):  ja3_freq/hassh_freq/http_ua_freq=0.0 + tls/http/dns raw counts
        F8        (7):  src_* derived from source_stats
        CNN     (640):  size_dir_seq_1..128, tcp_flags_seq_1..128, iat_log_ms_seq_1..128,
                        iat_rtt_bin_seq_1..128, entropy_bin_seq_1..128

    Returns:
        (total_flows, labeled_flows)
    """
    import json
    import math

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # ── 1. Load all events with evidence_bits grouped by src_ip ──
    # events.ts is ISO8601; convert once to epoch for fast window comparison.
    events_by_ip: dict = {}
    for row in conn.execute(
        "SELECT ts, source_ip, evidence_bits FROM events "
        "WHERE source_ip IS NOT NULL AND source_ip != '' AND evidence_bits > 0"
    ).fetchall():
        ep = _iso_to_epoch(row["ts"])
        if ep:
            ip = row["source_ip"]
            events_by_ip.setdefault(ip, []).append((ep, int(row["evidence_bits"])))
    for ip in events_by_ip:
        events_by_ip[ip].sort()

    # ── 2. Load source_stats → F8 derived features ──
    source_stats: dict = {}
    for row in conn.execute("SELECT * FROM source_stats").fetchall():
        ip = row["src_ip"]
        try:
            ports  = json.loads(row["unique_ports"]  or "[]")
            protos = json.loads(row["unique_protos"] or "[]")
            dsts   = json.loads(row["unique_dsts"]   or "[]")
        except (json.JSONDecodeError, TypeError):
            ports = protos = dsts = []
        fc   = int(row["flow_count"] or 0)
        spps = float(row["sum_pps"]  or 0.0)
        t0   = _iso_to_epoch(row["first_seen"] or "")
        t1   = _iso_to_epoch(row["last_seen"]  or "")
        span = round(max(0.0, (t1 - t0) / 60.0), 3) if (t0 and t1) else 0.0
        source_stats[ip] = {
            "src_flow_count":    fc,
            "src_unique_ports":  len(ports),
            "src_unique_protos": len(protos),
            "src_unique_dsts":   len(dsts),
            "src_span_min":      span,
            "src_avg_pps":       round(spps / max(fc, 1), 4),
            # Port entropy: log2(n_distinct_ports + 1) — proxy for scanning diversity
            "src_port_entropy":  round(math.log2(len(ports) + 1), 4),
        }

    # ── 3. Load fingerprints → F7 raw counts (freq=0.0; no global table on-device) ──
    fingerprints: dict = {}
    for row in conn.execute("SELECT * FROM pcap_fingerprints").fetchall():
        fingerprints[row["flow_id"]] = {
            "tls_cipher_count":  int(row["tls_cipher_count"]  or 0),
            "tls_ext_count":     int(row["tls_ext_count"]     or 0),
            "http_header_count": int(row["http_header_count"] or 0),
            "dns_qname_len":     int(row["dns_qname_len"]     or 0),
        }

    # ── 4. Load CNN packet tokens (first 128 per flow) ──
    # Stored as (size_dir_token, flag_token, iat_log_ms_bin, iat_rtt_bin, entropy_bin)
    # All values are small ints (0-22 range) — Python int cache applies, memory efficient.
    packets_by_flow: dict = {}
    for row in conn.execute(
        "SELECT flow_id, size_dir_token, flag_token, iat_log_ms_bin, iat_rtt_bin, entropy_bin "
        "FROM pcap_packets WHERE seq_idx < 128 ORDER BY flow_id, seq_idx"
    ).fetchall():
        packets_by_flow.setdefault(row["flow_id"], []).append((
            int(row["size_dir_token"] or 0),
            int(row["flag_token"]     or 0),
            int(row["iat_log_ms_bin"] or 0),
            int(row["iat_rtt_bin"]    or 0),
            int(row["entropy_bin"]    or 0),
        ))

    # ── 5. Build CSV header ──
    identity_cols = ["flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "first_ts", "last_ts"]
    label_cols    = ["evidence_bits", "label", "label_name", "auth_failure_count", "auth_success_count"]
    xgb_f1_f6    = [
        # F1 identity (3)
        "dst_port", "ip_proto", "app_proto",
        # F2 volume (8) — includes 4 derived cols not stored in pcap_flows
        "pkts_fwd", "pkts_rev", "bytes_fwd", "bytes_rev",
        "bytes_per_pkt_fwd", "bytes_per_pkt_rev", "pkt_ratio", "byte_ratio",
        # F3 timing (10)
        "duration_ms", "rtt_ms", "iat_fwd_mean_ms", "iat_fwd_std_ms",
        "think_time_mean_ms", "think_time_std_ms", "iat_to_rtt", "pps", "bps", "payload_rtt_ratio",
        # F4 size shape (14)
        "n_events", "fwd_size_mean", "fwd_size_std", "fwd_size_min", "fwd_size_max",
        "rev_size_mean", "rev_size_std", "rev_size_max",
        "hist_tiny", "hist_small", "hist_medium", "hist_large", "hist_full", "frac_full",
        # F5 TCP behavior (11)
        "syn_count", "fin_count", "rst_count", "psh_count", "ack_only_count",
        "conn_state", "rst_frac", "syn_to_data", "psh_burst_max", "retransmit_est", "window_size_init",
        # F6 payload content (8)
        "entropy_first", "entropy_fwd_mean", "entropy_rev_mean",
        "printable_frac", "null_frac", "byte_std", "high_entropy_frac", "payload_len_first",
    ]
    xgb_f7 = [
        # freq=0.0 (no global fingerprint freq table on-device); raw counts from pcap_fingerprints
        "ja3_freq", "hassh_freq", "http_ua_freq",
        "tls_cipher_count", "tls_ext_count", "http_header_count", "dns_qname_len",
    ]
    xgb_f8 = [
        "src_flow_count", "src_unique_ports", "src_unique_protos", "src_unique_dsts",
        "src_span_min", "src_avg_pps", "src_port_entropy",
    ]
    cnn_cols = []
    for _ch in ("size_dir", "tcp_flags", "iat_log_ms", "iat_rtt_bin", "entropy_bin"):
        for _i in range(1, 129):
            cnn_cols.append(f"{_ch}_seq_{_i}")

    header = identity_cols + label_cols + xgb_f1_f6 + xgb_f7 + xgb_f8 + cnn_cols

    # ── 6. Iterate flows, correlate evidence, write rows ──
    flows  = conn.execute("SELECT * FROM pcap_flows ORDER BY first_ts").fetchall()
    total  = len(flows)
    labeled = 0

    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)

        for flow in flows:
            fid    = flow["flow_id"]
            src_ip = flow["src_ip"]

            # Evidence window bounds
            ft0       = _iso_to_epoch(flow["first_ts"] or "")
            ft1       = _iso_to_epoch(flow["last_ts"]  or "")
            win_start = ft0 - evidence_window_s
            win_end   = ft1 + evidence_window_s

            # Aggregate evidence_bits from all matching events in window
            acc_bits  = 0
            auth_fail = 0
            auth_ok   = 0
            for ev_ts, ev_bits in events_by_ip.get(src_ip, []):
                if win_start <= ev_ts <= win_end:
                    acc_bits |= ev_bits
                    if ev_bits & AUTH_FAILURE:
                        auth_fail += 1
                    if ev_bits & AUTH_SUCCESS:
                        auth_ok += 1

            label_int, label_name = _derive_label(acc_bits)
            if label_int is not None:
                labeled += 1

            # Derived F2 (computed from stored raw counters; not in pcap_flows schema)
            pkts_fwd  = int(flow["pkts_fwd"]  or 0)
            pkts_rev  = int(flow["pkts_rev"]  or 0)
            bytes_fwd = int(flow["bytes_fwd"] or 0)
            bytes_rev = int(flow["bytes_rev"] or 0)
            bppf = round(bytes_fwd / max(pkts_fwd, 1), 4)
            bppr = round(bytes_rev / pkts_rev, 4) if pkts_rev > 0 else ""
            pr   = round(pkts_fwd  / max(pkts_rev, 1),  6)
            br   = round(bytes_fwd / max(bytes_rev, 1), 6)

            # F7 and F8 lookups
            fp = fingerprints.get(fid, {})
            ss = source_stats.get(src_ip, {})

            # CNN token sequences — 5 channels × 128 positions, zero-padded
            pkts = packets_by_flow.get(fid, [])[:128]
            pad  = 128 - len(pkts)
            ch0  = [p[0] for p in pkts] + [0] * pad  # size_dir
            ch1  = [p[1] for p in pkts] + [0] * pad  # tcp_flags
            ch2  = [p[2] for p in pkts] + [0] * pad  # iat_log_ms
            ch3  = [p[3] for p in pkts] + [0] * pad  # iat_rtt_bin
            ch4  = [p[4] for p in pkts] + [0] * pad  # entropy_bin

            def _v(col):
                v = flow[col]
                return "" if v is None else v

            row = [
                # Identity
                fid, src_ip, flow["dst_ip"], _v("src_port"), _v("dst_port"),
                _v("first_ts"), _v("last_ts"),
                # Labels (ground truth from host evidence)
                acc_bits, label_int if label_int is not None else "", label_name,
                auth_fail, auth_ok,
                # F1
                _v("dst_port"), _v("ip_proto"), _v("app_proto"),
                # F2 (stored + 4 derived)
                pkts_fwd, pkts_rev, bytes_fwd, bytes_rev,
                bppf, bppr, pr, br,
                # F3
                _v("duration_ms"), _v("rtt_ms"), _v("iat_fwd_mean_ms"), _v("iat_fwd_std_ms"),
                _v("think_time_mean_ms"), _v("think_time_std_ms"), _v("iat_to_rtt"),
                _v("pps"), _v("bps"), _v("payload_rtt_ratio"),
                # F4
                _v("n_events"),
                _v("fwd_size_mean"), _v("fwd_size_std"), _v("fwd_size_min"), _v("fwd_size_max"),
                _v("rev_size_mean"), _v("rev_size_std"), _v("rev_size_max"),
                _v("hist_tiny"), _v("hist_small"), _v("hist_medium"),
                _v("hist_large"), _v("hist_full"), _v("frac_full"),
                # F5
                _v("syn_count"), _v("fin_count"), _v("rst_count"),
                _v("psh_count"), _v("ack_only_count"), _v("conn_state"),
                _v("rst_frac"), _v("syn_to_data"), _v("psh_burst_max"),
                _v("retransmit_est"), _v("window_size_init"),
                # F6
                _v("entropy_first"), _v("entropy_fwd_mean"), _v("entropy_rev_mean"),
                _v("printable_frac"), _v("null_frac"), _v("byte_std"),
                _v("high_entropy_frac"), _v("payload_len_first"),
                # F7 (freq=0.0 — no global fingerprint_freq table on-device)
                0.0, 0.0, 0.0,
                fp.get("tls_cipher_count", 0), fp.get("tls_ext_count", 0),
                fp.get("http_header_count", 0), fp.get("dns_qname_len", 0),
                # F8
                ss.get("src_flow_count", ""), ss.get("src_unique_ports", ""),
                ss.get("src_unique_protos", ""), ss.get("src_unique_dsts", ""),
                ss.get("src_span_min", ""), ss.get("src_avg_pps", ""),
                ss.get("src_port_entropy", ""),
            ]
            # CNN: 5 channels appended in order (size_dir, tcp_flags, iat_log_ms, iat_rtt_bin, entropy_bin)
            row.extend(ch0); row.extend(ch1); row.extend(ch2); row.extend(ch3); row.extend(ch4)
            writer.writerow(row)

    conn.close()
    return total, labeled


def main() -> None:
    ap = argparse.ArgumentParser(description="DFI agent standalone export")
    ap.add_argument("command", choices=["export"])
    ap.add_argument("--format", choices=["xgb", "cnn", "both", "labeled"], default="both")
    ap.add_argument("--buffer", "--db", required=True, help="Path to agent_buffer.db")
    ap.add_argument("--output", help="Output file (for single format)")
    ap.add_argument("--output-dir", help="Output directory (for both/labeled)")
    ap.add_argument("--window", type=float, default=120.0,
                    help="Evidence correlation window in seconds (labeled format, default 120)")
    args = ap.parse_args()

    db = args.buffer
    if args.format == "xgb":
        out = args.output or "dfi_xgb.csv"
        n = export_xgb(db, out)
        print(f"Exported {n} flows to {out}")
    elif args.format == "cnn":
        out = args.output or "dfi_cnn.csv"
        n = export_cnn(db, out)
        print(f"Exported {n} flows to {out}")
    elif args.format == "labeled":
        out = args.output or "dfi_labeled.csv"
        total, labeled = export_labeled(db, out, evidence_window_s=args.window)
        pct = round(100 * labeled / max(total, 1), 1)
        print(f"Exported {total} flows to {out} ({labeled} labeled = {pct}%)")
    else:
        out_dir = args.output_dir or "."
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        n1 = export_xgb(db, str(Path(out_dir) / "dfi_xgb.csv"))
        n2 = export_cnn(db, str(Path(out_dir) / "dfi_cnn.csv"))
        print(f"Exported {n1} XGB flows, {n2} CNN flows to {out_dir}/")


if __name__ == "__main__":
    main()
