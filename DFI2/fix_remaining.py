#!/usr/bin/env python3
"""Fix remaining windows_4 rows that weren't caught by the first round of mutations."""
import paramiko
import time

HOST = '192.168.0.100'
PORT = 22
USER = 'root'
PASS = 'CHANGE_ME'

def run_cmd(client, cmd, timeout=120):
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

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(HOST, port=PORT, username=USER, password=PASS, timeout=15)

print("=" * 60)
print("Fix remaining windows_4 rows")
print("=" * 60)

mutations = [
    # Fix remaining Failed password (21 rows)
    (
        "Fix remaining 'Failed password' entries (no event_type filter)",
        """ALTER TABLE dfi.evidence_events UPDATE event_type = 'auth_failure', evidence_mask_bit = 0, source_program = 'sshd' WHERE source_program = 'windows_4' AND source_log LIKE '%Failed password%'"""
    ),
    # Fix remaining Invalid user (21 rows)
    (
        "Fix remaining 'Invalid user' entries",
        """ALTER TABLE dfi.evidence_events UPDATE event_type = 'auth_failure', evidence_mask_bit = 0, source_program = 'sshd' WHERE source_program = 'windows_4' AND source_log LIKE '%Invalid user%'"""
    ),
    # Fix "Connection closed by invalid user" -> auth_failure/sshd (104K rows)
    (
        "Fix 'Connection closed by invalid user' entries (104K rows)",
        """ALTER TABLE dfi.evidence_events UPDATE event_type = 'auth_failure', evidence_mask_bit = 0, source_program = 'sshd' WHERE source_program = 'windows_4' AND source_log LIKE '%Connection closed by%'"""
    ),
    # Fix "Connection reset by" -> auth_failure/sshd
    (
        "Fix 'Connection reset by' entries",
        """ALTER TABLE dfi.evidence_events UPDATE event_type = 'auth_failure', evidence_mask_bit = 0, source_program = 'sshd' WHERE source_program = 'windows_4' AND source_log LIKE '%Connection reset by%'"""
    ),
    # Fix "Received disconnect" -> auth_failure/sshd
    (
        "Fix 'Received disconnect' entries (2.7K rows)",
        """ALTER TABLE dfi.evidence_events UPDATE event_type = 'auth_failure', evidence_mask_bit = 0, source_program = 'sshd' WHERE source_program = 'windows_4' AND source_log LIKE '%Received disconnect%'"""
    ),
    # Fix "Disconnected from" (non-authenticating) -> auth_failure/sshd
    (
        "Fix 'Disconnected from' entries (2.7K rows)",
        """ALTER TABLE dfi.evidence_events UPDATE event_type = 'auth_failure', evidence_mask_bit = 0, source_program = 'sshd' WHERE source_program = 'windows_4' AND source_log LIKE '%Disconnected from%'"""
    ),
    # Fix "error:" entries -> connection/sshd
    (
        "Fix 'error:' entries",
        """ALTER TABLE dfi.evidence_events UPDATE event_type = 'connection', evidence_mask_bit = 7, source_program = 'sshd' WHERE source_program = 'windows_4' AND source_log LIKE '%error:%'"""
    ),
    # Catch-all: any remaining windows_4 with sshd in source_log -> auth_failure/sshd
    (
        "Catch-all: remaining windows_4 with sshd -> auth_failure/sshd",
        """ALTER TABLE dfi.evidence_events UPDATE event_type = 'auth_failure', evidence_mask_bit = 0, source_program = 'sshd' WHERE source_program = 'windows_4' AND source_log LIKE '%sshd%'"""
    ),
]

for desc, sql in mutations:
    print(f"\n--- {desc} ---")
    run_cmd(client, f'clickhouse-client --query="{sql}"')

print("\nWaiting 15s for mutations to process...")
time.sleep(15)

# Verify
print("\n" + "=" * 60)
print("VERIFICATION")
print("=" * 60)

# Check pending mutations
print("\n--- Pending mutations ---")
run_cmd(client, """clickhouse-client --query="SELECT mutation_id, is_done, parts_to_do FROM system.mutations WHERE table = 'evidence_events' AND is_done = 0" """)

# Check remaining windows_4
print("\n--- Remaining windows_4 rows ---")
run_cmd(client, """clickhouse-client --query="SELECT source_program, event_type, count() FROM dfi.evidence_events WHERE source_program = 'windows_4' GROUP BY source_program, event_type ORDER BY count() DESC" """)

# Check sshd rows
print("\n--- sshd rows (final) ---")
run_cmd(client, """clickhouse-client --query="SELECT source_program, event_type, count() FROM dfi.evidence_events WHERE source_program = 'sshd' GROUP BY source_program, event_type ORDER BY count() DESC" """)

# Total event distribution
print("\n--- Full event distribution ---")
run_cmd(client, """clickhouse-client --query="SELECT source_program, event_type, count() FROM dfi.evidence_events GROUP BY source_program, event_type ORDER BY count() DESC LIMIT 30" """)

# Check service still running
print("\n--- Service status ---")
run_cmd(client, 'systemctl status dfi2-evidence-ingest --no-pager')

# Check last 20 service logs
print("\n--- Service logs (last 20 lines) ---")
run_cmd(client, 'journalctl -u dfi2-evidence-ingest --no-pager -n 20')

client.close()
print("\n" + "=" * 60)
print("ALL DONE")
print("=" * 60)
