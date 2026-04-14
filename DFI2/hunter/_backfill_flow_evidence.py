#!/usr/bin/env python3
"""Backfill loop — runs flow_evidence_enrich batches as fast as possible until caught up."""
import logging
import subprocess
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

batch = 0
while True:
    result = subprocess.run(
        [sys.executable, '/opt/dfi2/hunter/flow_evidence_enrich.py'],
        capture_output=True, text=True
    )
    output = (result.stdout + result.stderr).strip()
    if output:
        logging.info('[batch %d] %s', batch, output)
    batch += 1
    if 'no new scored' in output:
        logging.info('backfill complete after %d batches', batch)
        break
