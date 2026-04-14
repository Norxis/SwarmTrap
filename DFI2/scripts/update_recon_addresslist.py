#!/usr/bin/env python3
"""Sync watchlist IPs to MikroTik address list (diff-based, CIDR-aggregated).

Source: /opt/dfi-hunter/watchlist.db — all active (non-expired) entries.
Only honeypot-backed IPs should be in the watchlist (xgb_scorer promote disabled 2026-03-24).

Staged CIDR aggregation:
  Stage 1: >= 5 IPs in a /24       → push as /24
  Stage 2: >= 5 hot /24s in a /20  → push as /20
           4/4 hot /24s in a /22   → push as /22
  Remainder: individual /32s

Maintains local state file. Uses pipelined SSH for fast batch operations.
"""
import json
import logging
import os
import re
import sqlite3
import time
from collections import defaultdict
from ipaddress import IPv4Address

import paramiko

MK_HOST = '172.16.3.1'
MK_PORT = 12315
MK_USER = 'D8Admin'
MK_PASS = 'CHANGE_ME'
WATCHLIST_DB = '/opt/dfi-hunter/watchlist.db'
STATE_FILE = '/opt/dfi2/scripts/.recon_addresslist_state.json'
STALE_FILE = '/opt/dfi2/scripts/.recon_stale_count.json'
WIPE_THRESHOLD = 5000
CHUNK_SIZE = 5000

MIN_IPS_PER_24 = 5
MIN_24S_PER_22 = 4
MIN_24S_PER_20 = 5

EXCLUDE_PREFIXES = ('216.126.0.', '38.247.', '192.168.', '172.16.', '10.', '108.181.161.199')

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
log = logging.getLogger('recon_addresslist')


def get_desired_entries():
    """Get all active watchlist IPs and aggregate into CIDRs."""
    con = sqlite3.connect(WATCHLIST_DB)
    now = time.time()
    rows = con.execute(
        "SELECT src_ip FROM watchlist WHERE expires_at IS NULL OR expires_at > ?",
        (now,)
    ).fetchall()
    con.close()
    all_ips = {r[0] for r in rows}
    log.info('Watchlist active IPs: %d', len(all_ips))

    # Filter out our own subnets
    filtered = {ip for ip in all_ips if not any(ip.startswith(p) for p in EXCLUDE_PREFIXES)}
    log.info('After excluding own subnets: %d', len(filtered))

    # Stage 1: group by /24
    slash24_ips = defaultdict(list)
    for ip in filtered:
        base = ip.rsplit('.', 1)[0] + '.0'
        slash24_ips[base].append(ip)

    hot_24s = {}
    cold_ips = set()
    for base, ips in slash24_ips.items():
        if len(ips) >= MIN_IPS_PER_24:
            hot_24s[base] = len(ips)
        else:
            cold_ips.update(ips)

    log.info('Stage 1: %d hot /24s, %d cold /32s', len(hot_24s), len(cold_ips))

    # Stage 2b: group hot /24s by /20
    slash20_groups = defaultdict(list)
    for base24 in hot_24s:
        addr = IPv4Address(base24)
        base20 = str(IPv4Address(int(addr) & 0xFFFFF000))
        slash20_groups[base20].append(base24)

    promoted_20s = set()
    consumed_24s = set()
    for base20, members in slash20_groups.items():
        if len(members) >= MIN_24S_PER_20:
            promoted_20s.add(base20 + '/20')
            consumed_24s.update(members)

    # Stage 2a: group remaining hot /24s by /22
    remaining_hot = {b for b in hot_24s if b not in consumed_24s}
    slash22_groups = defaultdict(list)
    for base24 in remaining_hot:
        addr = IPv4Address(base24)
        base22 = str(IPv4Address(int(addr) & 0xFFFFFC00))
        slash22_groups[base22].append(base24)

    promoted_22s = set()
    for base22, members in slash22_groups.items():
        if len(members) >= MIN_24S_PER_22:
            promoted_22s.add(base22 + '/22')
            consumed_24s.update(members)

    standalone_24s = {b + '/24' for b in hot_24s if b not in consumed_24s}
    entries = promoted_20s | promoted_22s | standalone_24s | cold_ips
    log.info('Final: %d /20s, %d /22s, %d /24s, %d /32s = %d total',
             len(promoted_20s), len(promoted_22s), len(standalone_24s), len(cold_ips), len(entries))
    return entries


def load_state():
    if not os.path.exists(STATE_FILE):
        return None
    try:
        with open(STATE_FILE) as f:
            return set(json.load(f).get('entries', []))
    except Exception as e:
        log.warning('Failed to load state: %s', e)
        return None


def save_state(entries):
    tmp = STATE_FILE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump({'entries': sorted(entries), 'updated_at': time.time()}, f)
    os.replace(tmp, STATE_FILE)


def get_mk_recon_entries(mk):
    stdin, stdout, _ = mk.exec_command('/ip/firewall/address-list/print where list=recon')
    output = stdout.read().decode()
    entries = set()
    for line in output.splitlines():
        m = re.search(r'recon\s+(\d+\.\d+\.\d+\.\d+(?:/\d+)?)', line)
        if m:
            entries.add(m.group(1))
    return entries


def rsc_import_commands(mk, commands):
    if not commands:
        return 0
    total_errors = 0
    n_chunks = (len(commands) + CHUNK_SIZE - 1) // CHUNK_SIZE
    for chunk_idx in range(n_chunks):
        chunk = commands[chunk_idx * CHUNK_SIZE:(chunk_idx + 1) * CHUNK_SIZE]
        rsc_name = f'dfi_recon_{chunk_idx}.rsc'
        sftp = mk.open_sftp()
        with sftp.file(rsc_name, 'w') as f:
            f.write('\n'.join(chunk) + '\n')
        sftp.close()
        stdin, stdout, stderr = mk.exec_command(f'/import file-name={rsc_name}')
        out = stdout.read().decode()
        err = stderr.read().decode()
        if 'failure' in (out + err).lower():
            total_errors += 1
            log.warning('Chunk %d error: %s %s', chunk_idx + 1, out.strip(), err.strip())
        mk.exec_command(f'/file/remove {rsc_name}')
        log.info('Chunk %d/%d imported (%d cmds)', chunk_idx + 1, n_chunks, len(chunk))
    return total_errors


def main():
    desired = get_desired_entries()

    current = load_state()

    mk = paramiko.SSHClient()
    mk.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    mk.connect(MK_HOST, port=MK_PORT, username=MK_USER, password=MK_PASS,
               look_for_keys=False, allow_agent=False)

    if current is None:
        log.info('No local state — querying MikroTik')
        current = get_mk_recon_entries(mk)
        log.info('MikroTik has %d recon entries', len(current))

    to_add = desired - current
    to_remove = current - desired

    stale_total = 0
    if os.path.exists(STALE_FILE):
        try:
            with open(STALE_FILE) as f:
                stale_total = json.load(f).get('stale', 0)
        except Exception:
            pass
    stale_total += len(to_remove)

    log.info('Diff: add=%d remove=%d unchanged=%d stale_accumulated=%d/%d',
             len(to_add), len(to_remove), len(desired & current), stale_total, WIPE_THRESHOLD)

    if not to_add and not to_remove:
        log.info('Nothing to do')
        mk.close()
        save_state(desired)
        return

    if stale_total >= WIPE_THRESHOLD:
        log.info('Stale threshold reached — bulk wipe + reimport')
        t0 = time.time()
        stdin, stdout, _ = mk.exec_command('/ip/firewall/address-list/remove [find where list=recon]')
        stdout.read()
        log.info('Wipe done in %.1fs', time.time() - t0)
        add_cmds = [f'/ip/firewall/address-list/add list=recon address={e}' for e in sorted(desired)]
        t0 = time.time()
        errors = rsc_import_commands(mk, add_cmds)
        log.info('Reimport done in %.1fs errors=%d', time.time() - t0, errors)
        stale_total = 0
        new_state = desired
    else:
        if to_remove:
            log.info('Skipping %d removes (stale %d/%d)', len(to_remove), stale_total, WIPE_THRESHOLD)
        if to_add:
            add_cmds = [f'/ip/firewall/address-list/add list=recon address={e}' for e in sorted(to_add)]
            t0 = time.time()
            errors = rsc_import_commands(mk, add_cmds)
            log.info('Add done in %.1fs errors=%d', time.time() - t0, errors)
        new_state = current | to_add

    mk.close()
    save_state(new_state)
    with open(STALE_FILE, 'w') as f:
        json.dump({'stale': stale_total, 'updated_at': time.time()}, f)


if __name__ == '__main__':
    main()
