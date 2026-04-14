#!/usr/bin/env python3
"""Check remaining windows_4 rows to understand what patterns they match."""
import paramiko

HOST = '192.168.0.100'
PORT = 22
USER = 'root'
PASS = 'CHANGE_ME'

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
    return out, err, rc

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(HOST, port=PORT, username=USER, password=PASS, timeout=15)

# Sample some remaining windows_4 rows to see what's in source_log
print("=== Sample source_log from remaining windows_4/unknown rows ===")
run_cmd(client, """clickhouse-client --query="SELECT substring(source_log, 1, 200) AS log_sample FROM dfi.evidence_events WHERE source_program = 'windows_4' AND event_type = 'unknown' LIMIT 20" """)

# Check if any mutations are still running
print("\n=== Check pending mutations ===")
run_cmd(client, """clickhouse-client --query="SELECT database, table, mutation_id, is_done, parts_to_do FROM system.mutations WHERE table = 'evidence_events' ORDER BY create_time DESC LIMIT 10" """)

# Deeper analysis: what patterns exist?
print("\n=== Pattern analysis of remaining windows_4 rows ===")
run_cmd(client, """clickhouse-client --query="
SELECT
    multiIf(
        source_log LIKE '%Failed password%', 'Failed password',
        source_log LIKE '%Invalid user%', 'Invalid user',
        source_log LIKE '%Connection closed by authenticating%', 'Connection closed auth',
        source_log LIKE '%Disconnected from authenticating%', 'Disconnected auth',
        source_log LIKE '%Accepted password%', 'Accepted password',
        source_log LIKE '%Accepted publickey%', 'Accepted publickey',
        source_log LIKE '%Connection closed by%', 'Connection closed other',
        source_log LIKE '%Disconnected from%', 'Disconnected other',
        source_log LIKE '%session opened%', 'session opened',
        source_log LIKE '%session closed%', 'session closed',
        source_log LIKE '%error:%', 'error',
        source_log LIKE '%pam_unix%', 'pam_unix',
        source_log LIKE '%Received disconnect%', 'Received disconnect',
        source_log LIKE '%maximum authentication%', 'max auth attempts',
        'other'
    ) AS pattern,
    count() AS cnt
FROM dfi.evidence_events
WHERE source_program = 'windows_4' AND event_type = 'unknown'
GROUP BY pattern
ORDER BY cnt DESC
" """)

client.close()
