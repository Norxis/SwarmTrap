#!/usr/bin/env python3
# DEPRECATED 2026-03-09 — dfi_norm DB dropped. Norm data now comes from:
#   dfi.v_xgb WHERE label = 5  (background norm)
#   dfi_dirty.v_xgb            (watchlist, synthetic label=6)
#   dfi_clean.v_xgb            (clean, synthetic label=7)
# This script will fail — kept for historical reference only.
"""
Refresh the dfi_norm.standard_norm materialized table.

Samples 5M random rows from dfi_norm.v_xgb_norm, excluding IPs
flagged by RECON v2 (recon_prob >= 0.7). Also recreates the
standard_norm_recon view (54 features for RECON training).

Usage:
    python3 refresh_standard_norm.py [--rows 5000000] [--recon-threshold 0.7]
"""
import argparse
import os
import time

from clickhouse_driver import Client

CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))

RECON_EXCLUDED = [
    'ja3_freq', 'tls_version', 'tls_cipher_count', 'tls_ext_count', 'tls_has_sni',
    'hassh_freq', 'ssh_kex_count',
    'http_method', 'http_uri_len', 'http_header_count', 'http_ua_freq', 'http_has_body', 'http_status',
    'dns_qtype', 'dns_qname_len',
    'src_flow_count', 'src_unique_ports', 'src_unique_protos', 'src_unique_dsts', 'src_span_min', 'src_avg_pps',
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rows', type=int, default=5000000)
    ap.add_argument('--recon-threshold', type=float, default=0.7)
    args = ap.parse_args()

    ch = Client(CH_HOST, port=CH_PORT)
    start = time.time()

    # Count available clean norm rows
    recon_ips = ch.execute(
        f"SELECT uniq(src_ip) FROM dfi_recon.recon_flows WHERE recon_prob >= {args.recon_threshold}"
    )[0][0]
    print(f'RECON IPs to exclude (prob >= {args.recon_threshold}): {recon_ips}')

    # Drop and recreate
    ch.execute('DROP TABLE IF EXISTS dfi_norm.standard_norm')

    create_q = (
        f"CREATE TABLE dfi_norm.standard_norm ENGINE = MergeTree() "
        f"ORDER BY (dst_port, flow_id) AS "
        f"SELECT * FROM dfi_norm.v_xgb_norm "
        f"WHERE flow_id NOT IN ("
        f"  SELECT flow_id FROM dfi_norm.flows "
        f"  WHERE src_ip IN (SELECT DISTINCT src_ip FROM dfi_recon.recon_flows WHERE recon_prob >= {args.recon_threshold})"
        f") "
        f"ORDER BY rand() LIMIT {args.rows}"
    )
    ch.execute(create_q)

    # Recreate RECON view
    ch.execute('DROP VIEW IF EXISTS dfi_norm.standard_norm_recon')
    excl = ', '.join(RECON_EXCLUDED)
    ch.execute(
        f"CREATE VIEW dfi_norm.standard_norm_recon AS "
        f"SELECT * EXCEPT({excl}) FROM dfi_norm.standard_norm"
    )

    elapsed = time.time() - start

    # Summary
    count = ch.execute('SELECT count() FROM dfi_norm.standard_norm')[0][0]
    ports = ch.execute('SELECT uniq(dst_port) FROM dfi_norm.standard_norm')[0][0]
    recon_view = ch.execute('SELECT count() FROM dfi_norm.standard_norm_recon')[0][0]

    print(f'standard_norm: {count:,} rows, {ports:,} unique ports')
    print(f'standard_norm_recon: {recon_view:,} rows (54 features)')
    print(f'Completed in {elapsed:.1f}s')


if __name__ == '__main__':
    main()
