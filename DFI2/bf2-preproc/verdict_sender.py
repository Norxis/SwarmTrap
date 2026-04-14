#!/usr/bin/env python3
"""
verdict_sender.py — CH GOD sends settled verdicts to ARM GOD

Runs at :07/:12/:17/:22/:27/:32/:37/:42/:47/:52/:57 (cron: 7-59/5)
4 minutes after ip_reputation_builder (:03/:08/...)

Queries CH for settled IPs → publishes to NATS → ARM receives → eSwitch DROP
"""

import logging
import os
import sys

from clickhouse_driver import Client

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('verdict_sender')


def run(ch_host='localhost', arm_host='192.168.100.2'):
    ch = Client(host=ch_host)

    settled = ch.execute("""
        SELECT src_ip
        FROM dfi.ip_reputation FINAL
        WHERE (
            (has_any_evidence = 1 AND state = 2)
            OR (state = 1 AND label_confidence >= 0.90)
            OR (watchlist_source IN ('blind_scanner'))
        )
    """)

    if not settled:
        log.info("No settled IPs")
        return

    log.info("Found %d settled IPs", len(settled))

    # Write IP list to file, SCP to ARM
    import tempfile, subprocess
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        for (ip,) in settled:
            f.write(f"{ip}\n")
        tmp_path = f.name

    result = subprocess.run(
        ["scp", "-o", "StrictHostKeyChecking=no",
         tmp_path, f"ubuntu@{arm_host}:/tmp/verdicts.txt"],
        capture_output=True, text=True, timeout=30
    )
    os.unlink(tmp_path)

    if result.returncode == 0:
        # Move to final path on ARM
        subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no",
             f"ubuntu@{arm_host}",
             "sudo mv /tmp/verdicts.txt /var/lib/dfi-preproc/verdicts.txt"],
            capture_output=True, timeout=10
        )
        log.info("Sent %d verdict IPs to ARM", len(settled))
    else:
        log.error("SCP failed: %s", result.stderr)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--ch-host', default='localhost')
    parser.add_argument('--arm-host', default='192.168.100.2')
    args = parser.parse_args()

    run(args.ch_host, args.arm_host)


if __name__ == '__main__':
    main()
