#!/usr/bin/env python3
"""Export attack (labels 1,2,3) and recon (label 0) from dfi.flows on PV1.

Exports all rows in a single clickhouse-client call (max CPU, one scan),
then splits into 1M-row chunks with header preserved in each chunk.

Output:
  /mnt/dfi-data/ml/data/attack/attack_chunk_000.csv  (1M rows each)
  /mnt/dfi-data/ml/data/recon/recon_chunk_000.csv    (1M rows each)

Raw files kept for reference (delete manually if disk is tight).
"""
import os
import subprocess
import time

BASE = '/mnt/dfi-data/ml/data'
CHUNK_SIZE = 1_000_000


def run_export(db, labels_str, out_path):
    """Single clickhouse-client call — one full table scan, max threads."""
    where = (
        f'capture_depth >= 2 '
        f'AND flow_id IN (SELECT flow_id FROM {db}.labels WHERE label IN ({labels_str}))'
    )
    query = f'SELECT * FROM {db}.flows WHERE {where}'
    print(f'[export] {query[:140]}', flush=True)
    t0 = time.time()
    with open(out_path, 'w') as f:
        subprocess.run(
            ['clickhouse-client',
             f'--query={query} FORMAT CSVWithNames',
             '--max_threads=0', '--max_memory_usage=0'],
            stdout=f, check=True,
        )
    elapsed = time.time() - t0
    size_mb = os.path.getsize(out_path) / 1024 ** 2
    print(f'[export] done: {size_mb:.0f} MB in {elapsed:.0f}s', flush=True)


def split_csv(src, out_dir, prefix):
    """Split CSV into CHUNK_SIZE-row files, header in every chunk."""
    os.makedirs(out_dir, exist_ok=True)
    t0 = time.time()
    total = 0
    chunk_idx = 0
    with open(src, 'r') as f:
        header = f.readline()
        while True:
            chunk_path = os.path.join(out_dir, f'{prefix}_chunk_{chunk_idx:03d}.csv')
            written = 0
            with open(chunk_path, 'w') as out:
                out.write(header)
                for line in f:
                    out.write(line)
                    written += 1
                    if written >= CHUNK_SIZE:
                        break
            if written == 0:
                os.remove(chunk_path)
                break
            size_mb = os.path.getsize(chunk_path) / 1024 ** 2
            print(f'  {prefix}_chunk_{chunk_idx:03d}: {written:,} rows  {size_mb:.0f} MB', flush=True)
            total += written
            if written < CHUNK_SIZE:
                break
            chunk_idx += 1
    chunks = chunk_idx + 1
    print(f'  Split done: {total:,} rows → {chunks} chunks in {time.time()-t0:.0f}s', flush=True)
    return total


def main():
    os.makedirs(BASE, exist_ok=True)

    # ── Attack: labels 1,2,3 ──────────────────────────────────────────────────
    print('\n=== ATTACK (labels 1,2,3) ===', flush=True)
    attack_raw = os.path.join(BASE, 'attack_raw.csv')
    run_export('dfi', '1,2,3', attack_raw)
    split_csv(attack_raw, os.path.join(BASE, 'attack'), 'attack')

    # ── Recon: label 0 ────────────────────────────────────────────────────────
    print('\n=== RECON (label 0) ===', flush=True)
    recon_raw = os.path.join(BASE, 'recon_raw.csv')
    run_export('dfi', '0', recon_raw)
    split_csv(recon_raw, os.path.join(BASE, 'recon'), 'recon')

    print('\nALL DONE', flush=True)


if __name__ == '__main__':
    main()
