#!/usr/bin/env python3
"""Deploy fixed evidence_ingest.py to PV1, restart service, fix misclassified rows."""
import paramiko
import sys
import time

HOST = '192.168.0.100'
PORT = 22
USER = 'root'
PASS = 'CHANGE_ME'

LOCAL_FILE = '/home/colo8gent/DFI2/labeler/evidence_ingest.py'
REMOTE_FILE = '/opt/dfi2/labeler/evidence_ingest.py'

SERVICE_NAMES = [
    'dfi2-evidence-ingest',
    'dfi-evidence-ingest',
    'evidence-ingest',
    'evidence_ingest',
]

def ssh_connect():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, port=PORT, username=USER, password=PASS, timeout=15)
    return client

def run_cmd(client, cmd, timeout=60):
    print(f"\n>>> {cmd}")
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode('utf-8', errors='replace')
    err = stderr.read().decode('utf-8', errors='replace')
    rc = stdout.channel.recv_exit_status()
    if out.strip():
        print(out.strip())
    if err.strip():
        print(f"STDERR: {err.strip()}")
    print(f"[exit={rc}]")
    return out, err, rc

def main():
    print("=" * 60)
    print("STEP 1: SCP fixed evidence_ingest.py to PV1")
    print("=" * 60)
    client = ssh_connect()

    # Ensure target directory exists
    run_cmd(client, f'mkdir -p /opt/dfi2/labeler')

    # SCP file
    sftp = client.open_sftp()
    print(f"\nUploading {LOCAL_FILE} -> {REMOTE_FILE}")
    sftp.put(LOCAL_FILE, REMOTE_FILE)
    # Verify
    stat = sftp.stat(REMOTE_FILE)
    print(f"Uploaded OK - size={stat.st_size} bytes")
    sftp.close()

    # Verify content
    run_cmd(client, f'head -5 {REMOTE_FILE}')
    run_cmd(client, f'wc -l {REMOTE_FILE}')

    print("\n" + "=" * 60)
    print("STEP 2: Restart evidence ingest service")
    print("=" * 60)

    # Find the right service name
    found_service = None
    for svc in SERVICE_NAMES:
        out, err, rc = run_cmd(client, f'systemctl list-unit-files | grep -i {svc}')
        if rc == 0 and out.strip():
            found_service = svc
            print(f"\nFound service: {svc}")
            break

    if not found_service:
        # Try broader search
        print("\nTrying broader search...")
        out, err, rc = run_cmd(client, 'systemctl list-unit-files | grep -i evidence')
        if out.strip():
            # Extract first match
            line = out.strip().split('\n')[0]
            found_service = line.split()[0].replace('.service', '')
            print(f"Found service from broad search: {found_service}")
        else:
            print("No evidence service found, trying all dfi2 services...")
            run_cmd(client, 'systemctl list-unit-files | grep -i dfi')

    if found_service:
        run_cmd(client, f'systemctl restart {found_service}')
        time.sleep(2)
        run_cmd(client, f'systemctl status {found_service}')
    else:
        print("WARNING: Could not find evidence ingest service. Checking all dfi services:")
        run_cmd(client, 'systemctl list-unit-files | grep -i dfi')

    print("\n" + "=" * 60)
    print("STEP 3: Check scale of misclassified rows")
    print("=" * 60)

    run_cmd(client, """clickhouse-client --query="SELECT source_program, event_type, count() FROM dfi.evidence_events WHERE source_program = 'windows_4' GROUP BY source_program, event_type ORDER BY count() DESC" """)

    print("\n" + "=" * 60)
    print("STEP 4: Run ClickHouse mutations to fix misclassified rows")
    print("=" * 60)

    mutations = [
        # Fix "Failed password" -> auth_failure/sshd
        (
            "Fix 'Failed password' entries",
            """ALTER TABLE dfi.evidence_events UPDATE event_type = 'auth_failure', evidence_mask_bit = 0, source_program = 'sshd' WHERE source_program = 'windows_4' AND event_type = 'unknown' AND source_log LIKE '%Failed password%'"""
        ),
        # Fix "Invalid user" -> auth_failure/sshd
        (
            "Fix 'Invalid user' entries",
            """ALTER TABLE dfi.evidence_events UPDATE event_type = 'auth_failure', evidence_mask_bit = 0, source_program = 'sshd' WHERE source_program = 'windows_4' AND event_type = 'unknown' AND source_log LIKE '%Invalid user%'"""
        ),
        # Fix "Connection closed / Disconnected from authenticating" -> auth_failure/sshd
        (
            "Fix 'Connection closed / Disconnected from authenticating' entries",
            """ALTER TABLE dfi.evidence_events UPDATE event_type = 'auth_failure', evidence_mask_bit = 0, source_program = 'sshd' WHERE source_program = 'windows_4' AND event_type = 'unknown' AND (source_log LIKE '%Connection closed by authenticating%' OR source_log LIKE '%Disconnected from authenticating%')"""
        ),
        # Fix "Accepted password / Accepted publickey" -> auth_success/sshd
        (
            "Fix 'Accepted password / Accepted publickey' entries",
            """ALTER TABLE dfi.evidence_events UPDATE event_type = 'auth_success', evidence_mask_bit = 1, source_program = 'sshd' WHERE source_program = 'windows_4' AND event_type = 'unknown' AND (source_log LIKE '%Accepted password%' OR source_log LIKE '%Accepted publickey%')"""
        ),
    ]

    for desc, sql in mutations:
        print(f"\n--- {desc} ---")
        run_cmd(client, f'clickhouse-client --query="{sql}"', timeout=120)

    # Wait for mutations to process
    print("\nWaiting 10s for mutations to process...")
    time.sleep(10)

    print("\n" + "=" * 60)
    print("STEP 5: Verify mutations")
    print("=" * 60)

    # Check pending mutations
    print("\n--- Pending mutations ---")
    run_cmd(client, """clickhouse-client --query="SELECT database, table, mutation_id, command, is_done FROM system.mutations WHERE table = 'evidence_events' AND is_done = 0" """)

    # Check remaining windows_4 rows
    print("\n--- Remaining windows_4 rows ---")
    run_cmd(client, """clickhouse-client --query="SELECT source_program, event_type, count() FROM dfi.evidence_events WHERE source_program = 'windows_4' GROUP BY source_program, event_type ORDER BY count() DESC" """)

    # Check new sshd rows
    print("\n--- sshd rows (after fix) ---")
    run_cmd(client, """clickhouse-client --query="SELECT source_program, event_type, count() FROM dfi.evidence_events WHERE source_program = 'sshd' GROUP BY source_program, event_type ORDER BY count() DESC" """)

    print("\n" + "=" * 60)
    print("STEP 6: Check service logs")
    print("=" * 60)

    if found_service:
        run_cmd(client, f'journalctl -u {found_service} --no-pager -n 20')
    else:
        for svc in SERVICE_NAMES:
            out, err, rc = run_cmd(client, f'journalctl -u {svc} --no-pager -n 5 2>/dev/null')
            if out.strip() and 'No entries' not in out:
                break

    client.close()
    print("\n" + "=" * 60)
    print("DEPLOYMENT COMPLETE")
    print("=" * 60)

if __name__ == '__main__':
    main()
