#!/usr/bin/env python3
"""
DFI2 Deployment Script — deploys dashboard and ML pipeline to PV1 via Paramiko.
Target: 192.168.0.100:22, root
"""

import sys
import time
import paramiko
import os

# ─── Connection config ───────────────────────────────────────────────────────
HOST     = "192.168.0.100"
PORT     = 22
USER     = "root"
PASSWORD = "CHANGE_ME"

# ─── Local source files ───────────────────────────────────────────────────────
LOCAL_BASE      = "/home/colo8gent/DFI2"
DASHBOARD_FILES = [("dashboard/dashboard.py", "/opt/dfi2/dashboard/dashboard.py")]
ML_FILES        = [
    ("ml/export.py",    "/opt/dfi2/ml/export.py"),
    ("ml/train_xgb.py", "/opt/dfi2/ml/train_xgb.py"),
    ("ml/train_cnn.py", "/opt/dfi2/ml/train_cnn.py"),
    ("ml/score.py",     "/opt/dfi2/ml/score.py"),
]

SYSTEMD_UNIT = """\
[Unit]
Description=DFI2 Dashboard - Streamlit
After=network-online.target clickhouse-server.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 -m streamlit run /opt/dfi2/dashboard/dashboard.py --server.port 8501 --server.headless true
WorkingDirectory=/opt/dfi2
Environment=CH_HOST=localhost
Environment=CH_PORT=9000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

PIP_CMD = (
    "pip3 install --break-system-packages -q "
    "streamlit pandas xgboost torch clickhouse-driver 2>/dev/null || "
    "pip3 install -q streamlit pandas xgboost torch clickhouse-driver"
)

# ─── Helpers ──────────────────────────────────────────────────────────────────

def banner(msg):
    print(f"\n{'─'*60}")
    print(f"  {msg}")
    print(f"{'─'*60}")

def ok(msg):
    print(f"  [OK]   {msg}")

def info(msg):
    print(f"  [INFO] {msg}")

def warn(msg):
    print(f"  [WARN] {msg}")

def fail(msg):
    print(f"  [FAIL] {msg}")


def run_cmd(ssh, cmd, check=True, timeout=300):
    """Run a command over SSH; return (exit_status, stdout, stderr)."""
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    exit_status = stdout.channel.recv_exit_status()
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if check and exit_status != 0:
        raise RuntimeError(f"Command failed (exit {exit_status}): {cmd}\nSTDERR: {err}")
    return exit_status, out, err


def connect():
    banner("Step 1 — Connecting to PV1 (192.168.0.100:22)")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, port=PORT, username=USER, password=PASSWORD,
                   look_for_keys=False, allow_agent=False, timeout=20)
    ok(f"Connected as {USER}@{HOST}")
    return client


def create_remote_dirs(ssh):
    banner("Step 2 — Creating remote directories")
    run_cmd(ssh, "mkdir -p /opt/dfi2/dashboard /opt/dfi2/ml")
    ok("Directories /opt/dfi2/dashboard and /opt/dfi2/ml created")


def upload_files(ssh):
    banner("Step 3 — Uploading files via SFTP")
    sftp = ssh.open_sftp()
    all_files = DASHBOARD_FILES + ML_FILES
    for local_rel, remote_path in all_files:
        local_abs = os.path.join(LOCAL_BASE, local_rel)
        if not os.path.exists(local_abs):
            fail(f"Local file missing: {local_abs}")
            raise FileNotFoundError(local_abs)
        sftp.put(local_abs, remote_path)
        ok(f"Uploaded {local_rel}  ->  {remote_path}")
    sftp.close()


def install_dependencies(ssh):
    banner("Step 4 — Installing Python dependencies (may take several minutes)")
    info("Running pip3 install on PV1 …")
    exit_status, out, err = run_cmd(ssh, PIP_CMD, check=False, timeout=600)
    if exit_status == 0:
        ok("pip3 install completed successfully")
    else:
        warn(f"pip3 install returned exit {exit_status} — continuing anyway")
        if err:
            info(f"stderr snippet: {err[:400]}")


def setup_and_start_service(ssh):
    banner("Step 5 — Setting up systemd service (dfi2-dashboard)")

    # Check if service unit file already exists
    rc, out, err = run_cmd(ssh, "test -f /etc/systemd/system/dfi2-dashboard.service && echo EXISTS || echo MISSING", check=False)
    service_exists = "EXISTS" in out

    if service_exists:
        info("Service unit file already exists — skipping creation")
    else:
        info("Service unit file not found — creating /etc/systemd/system/dfi2-dashboard.service")
        # Write via echo to avoid quoting nightmares — use a heredoc trick over SSH
        sftp = ssh.open_sftp()
        with sftp.open("/etc/systemd/system/dfi2-dashboard.service", "w") as f:
            f.write(SYSTEMD_UNIT)
        sftp.close()
        ok("Service unit file written")

        run_cmd(ssh, "systemctl daemon-reload")
        ok("systemctl daemon-reload completed")

        run_cmd(ssh, "systemctl enable dfi2-dashboard")
        ok("dfi2-dashboard enabled")

    # Restart (works whether it existed before or was just created)
    info("Restarting dfi2-dashboard …")
    rc, out, err = run_cmd(ssh, "systemctl restart dfi2-dashboard 2>&1; echo EXIT:$?", check=False)
    if "EXIT:0" in out or rc == 0:
        ok("dfi2-dashboard restarted successfully")
    else:
        warn(f"Restart returned non-zero — may still be starting. Output: {out[:300]}")


def verify_port(ssh):
    banner("Step 6 — Verifying dashboard on port 8501")
    info("Waiting 5 seconds for service to bind …")
    time.sleep(5)

    rc, out, err = run_cmd(
        ssh,
        "ss -tlnp | grep ':8501' || netstat -tlnp 2>/dev/null | grep ':8501' || echo NOT_LISTENING",
        check=False,
    )
    if "NOT_LISTENING" in out or out.strip() == "":
        warn("Port 8501 does not appear to be listening yet — checking service status …")
        _, status_out, _ = run_cmd(ssh, "systemctl status dfi2-dashboard --no-pager -l", check=False)
        info(f"Service status:\n{status_out[:800]}")
    else:
        ok(f"Port 8501 is LISTENING. Dashboard reachable at http://{HOST}:8501")
        info(f"Socket info: {out.strip()}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "="*60)
    print("  DFI2 Deployment — PV1 (192.168.0.100)")
    print("="*60)

    ssh = None
    try:
        ssh = connect()
        create_remote_dirs(ssh)
        upload_files(ssh)
        install_dependencies(ssh)
        setup_and_start_service(ssh)
        verify_port(ssh)

        banner("Deployment complete")
        ok("All steps finished. DFI2 is deployed on PV1.")
        print(f"\n  Dashboard URL : http://{HOST}:8501\n")

    except Exception as exc:
        fail(f"Deployment aborted: {exc}")
        sys.exit(1)
    finally:
        if ssh:
            ssh.close()
            info("SSH connection closed.")


if __name__ == "__main__":
    main()
