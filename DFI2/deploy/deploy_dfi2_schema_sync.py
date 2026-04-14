#!/usr/bin/env python3
"""
DFI2 Schema + Sync/Labeler/Classifier deployment to PV1 (192.168.0.100)
Deploys:
  - schema/03_buffers.sql  -> /tmp/dfi2_schema/
  - sync/{config,pull_aio,push_watchlist}.py -> /opt/dfi2/sync/
  - labeler/{__init__,labeler,evidence_ingest}.py -> /opt/dfi2/labeler/
  - classifier/{__init__,classifier,watchlist_push}.py -> /opt/dfi2/classifier/
"""

import sys
import os
import paramiko
import traceback

# ── Connection ─────────────────────────────────────────────────────────────────
HOST     = "192.168.0.100"
PORT     = 22
USER     = "root"
PASSWORD = "CHANGE_ME"

# ── Local source root ───────────────────────────────────────────────────────────
LOCAL_ROOT = "/home/colo8gent/DFI2"

# ── File manifest ───────────────────────────────────────────────────────────────
TRANSFERS = [
    # (local_relative_path,              remote_path)
    ("schema/03_buffers.sql",            "/tmp/dfi2_schema/03_buffers.sql"),
    ("sync/config.py",                   "/opt/dfi2/sync/config.py"),
    ("sync/pull_aio.py",                 "/opt/dfi2/sync/pull_aio.py"),
    ("sync/push_watchlist.py",           "/opt/dfi2/sync/push_watchlist.py"),
    ("labeler/__init__.py",              "/opt/dfi2/labeler/__init__.py"),
    ("labeler/labeler.py",               "/opt/dfi2/labeler/labeler.py"),
    ("labeler/evidence_ingest.py",       "/opt/dfi2/labeler/evidence_ingest.py"),
    ("classifier/__init__.py",           "/opt/dfi2/classifier/__init__.py"),
    ("classifier/classifier.py",         "/opt/dfi2/classifier/classifier.py"),
    ("classifier/watchlist_push.py",     "/opt/dfi2/classifier/watchlist_push.py"),
]

# ── Remote commands (run in order) ─────────────────────────────────────────────
REMOTE_DIRS_CMD = (
    "mkdir -p /opt/dfi2/sync /opt/dfi2/labeler /opt/dfi2/classifier /tmp/dfi2_schema"
)

SCHEMA_CMD = (
    "clickhouse-client --multiquery < /tmp/dfi2_schema/03_buffers.sql"
)

# Retire dfi2-log-bridge (merged into evidence_ingest)
BRIDGE_RETIRE_CMDS = [
    "systemctl stop dfi2-log-bridge 2>/dev/null || true",
    "systemctl disable dfi2-log-bridge 2>/dev/null || true",
]

# Update evidence-ingest systemd unit: add BRIDGE_HOST/PORT, remove POLL_INTERVAL
SYSTEMD_UNIT = "/etc/systemd/system/dfi2-evidence-ingest.service"
SYSTEMD_UPDATE_CMDS = [
    # Add BRIDGE_HOST/PORT if not already present
    f"grep -q BRIDGE_HOST {SYSTEMD_UNIT} || "
    f"sed -i '/^\\[Service\\]/a Environment=BRIDGE_HOST=127.0.0.1\\nEnvironment=BRIDGE_PORT=1514' {SYSTEMD_UNIT}",
    # Remove POLL_INTERVAL if present
    f"sed -i '/POLL_INTERVAL/d' {SYSTEMD_UNIT}",
    "systemctl daemon-reload",
]

SERVICE_CMDS = [
    "systemctl restart dfi2-labeler 2>/dev/null || true",
    "systemctl restart dfi2-classifier 2>/dev/null || true",
    "systemctl restart dfi2-evidence-ingest 2>/dev/null || true",
]

CRON_PULL = (
    r"crontab -l 2>/dev/null | grep -q pull_aio "
    r"|| (crontab -l 2>/dev/null; "
    r"echo '*/5 * * * * /usr/bin/python3 /opt/dfi2/sync/pull_aio.py "
    r">> /var/log/dfi2_pull.log 2>&1') | crontab -"
)

CRON_PUSH = (
    r"crontab -l 2>/dev/null | grep -q push_watchlist "
    r"|| (crontab -l 2>/dev/null; "
    r"echo '*/10 * * * * /usr/bin/python3 /opt/dfi2/sync/push_watchlist.py "
    r">> /var/log/dfi2_push.log 2>&1') | crontab -"
)

CH_VERIFY_CMD = 'clickhouse-client --query "SELECT 1"'


# ── Helpers ────────────────────────────────────────────────────────────────────
def banner(msg: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}")


def ok(msg: str) -> None:
    print(f"  [OK]  {msg}")


def fail(msg: str) -> None:
    print(f"  [FAIL] {msg}")


def run_cmd(client: paramiko.SSHClient, cmd: str, desc: str) -> bool:
    """Execute a remote command, print stdout/stderr, return success bool."""
    print(f"\n  >> {desc}")
    print(f"     cmd: {cmd}")
    _, stdout, stderr = client.exec_command(cmd, timeout=60)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    rc  = stdout.channel.recv_exit_status()
    if out:
        print(f"     stdout: {out}")
    if err:
        print(f"     stderr: {err}")
    print(f"     exit code: {rc}")
    if rc == 0:
        ok(desc)
        return True
    else:
        fail(f"{desc} (exit {rc})")
        return False


def sftp_put(sftp: paramiko.SFTPClient, local_rel: str, remote: str) -> bool:
    """Upload a single file via SFTP."""
    local = os.path.join(LOCAL_ROOT, local_rel)
    if not os.path.isfile(local):
        fail(f"Local file not found: {local}")
        return False
    try:
        sftp.put(local, remote)
        ok(f"Uploaded {local_rel} -> {remote}")
        return True
    except Exception as exc:
        fail(f"SFTP put {local_rel}: {exc}")
        return False


# ── Main ───────────────────────────────────────────────────────────────────────
def main() -> int:
    errors = 0

    # ── 1. Connect ────────────────────────────────────────────────────────────
    banner("Step 1 — SSH Connect to PV1 (192.168.0.100:22)")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=HOST,
            port=PORT,
            username=USER,
            password=PASSWORD,
            timeout=15,
            allow_agent=False,
            look_for_keys=False,
        )
        ok(f"Connected as {USER}@{HOST}:{PORT}")
    except Exception as exc:
        fail(f"SSH connection failed: {exc}")
        traceback.print_exc()
        return 1

    # ── 2. Create remote directories ──────────────────────────────────────────
    banner("Step 2 — Create Remote Directories")
    if not run_cmd(client, REMOTE_DIRS_CMD, "mkdir -p /opt/dfi2/{sync,labeler,classifier} /tmp/dfi2_schema"):
        errors += 1

    # ── 3. SFTP uploads ───────────────────────────────────────────────────────
    banner("Step 3 — SFTP File Uploads")
    try:
        sftp = client.open_sftp()
        for local_rel, remote_path in TRANSFERS:
            if not sftp_put(sftp, local_rel, remote_path):
                errors += 1
        sftp.close()
        ok("SFTP session closed")
    except Exception as exc:
        fail(f"SFTP session error: {exc}")
        traceback.print_exc()
        errors += 1

    # ── 4. Apply ClickHouse schema ────────────────────────────────────────────
    banner("Step 4 — Apply ClickHouse Schema (03_buffers.sql)")
    if not run_cmd(client, SCHEMA_CMD, "clickhouse-client --multiquery < 03_buffers.sql"):
        errors += 1

    # ── 5. Retire dfi2-log-bridge (merged into evidence_ingest) ──────────────
    banner("Step 5 — Retire dfi2-log-bridge")
    for cmd in BRIDGE_RETIRE_CMDS:
        run_cmd(client, cmd, cmd.split("||")[0].strip())

    # ── 6. Update evidence-ingest systemd unit ────────────────────────────────
    banner("Step 6 — Update evidence-ingest systemd unit (BRIDGE_HOST/PORT)")
    for cmd in SYSTEMD_UPDATE_CMDS:
        if not run_cmd(client, cmd, cmd[:60]):
            errors += 1

    # ── 7. Restart services ───────────────────────────────────────────────────
    banner("Step 7 — Restart DFI2 Services")
    for cmd in SERVICE_CMDS:
        svc = cmd.split()[2]  # e.g. "dfi2-labeler"
        if not run_cmd(client, cmd, f"systemctl restart {svc}"):
            errors += 1  # non-fatal if service doesn't exist

    # ── 8. Cron entries ───────────────────────────────────────────────────────
    banner("Step 8 — Verify / Add Cron Entries")
    if not run_cmd(client, CRON_PULL, "cron: pull_aio every 5 min"):
        errors += 1
    if not run_cmd(client, CRON_PUSH, "cron: push_watchlist every 10 min"):
        errors += 1

    # Show final crontab for confirmation
    run_cmd(client, "crontab -l 2>/dev/null", "crontab -l (current state)")

    # ── 9. Verify ClickHouse running ──────────────────────────────────────────
    banner("Step 9 — Verify ClickHouse Is Running")
    if not run_cmd(client, CH_VERIFY_CMD, 'clickhouse-client --query "SELECT 1"'):
        errors += 1

    # ── Done ──────────────────────────────────────────────────────────────────
    client.close()
    banner("Deployment Complete")
    if errors:
        print(f"  RESULT: {errors} step(s) had errors — review output above.")
        return 1
    else:
        print("  RESULT: All steps succeeded.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
