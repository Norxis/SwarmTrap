#!/usr/bin/env python3
"""
DFI2 Hunter deployment script to AIO server (192.168.0.113:2222).
Deploys hunter Python files, schema, and systemd service.

DO NOT FORGET OFFLOAD! — GRO/GSO/TSO/LRO must be disabled on the capture
interface before Hunter starts, otherwise AF_PACKET sees coalesced jumbo
frames instead of real packets. This script handles it automatically.
"""

import paramiko
import os
import sys
import time

# Connection parameters
HOST = "192.168.0.113"
PORT = 2222
USER = "colo8gent"
PASSWORD = "CHANGE_ME"

# Source paths
SRC_BASE = "/home/colo8gent/DFI2"

# DO NOT FORGET OFFLOAD! — capture interface must have hardware offloads disabled
CAPTURE_IFACE = "ens192"

NIC_OFFLOAD_SERVICE = f"""\
[Unit]
Description=Disable NIC offloads on capture interface — DO NOT FORGET OFFLOAD!
After=network-online.target
Before=dfi-hunter2.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ethtool -K {CAPTURE_IFACE} gro off gso off tso off lro off sg off tx off rx off

[Install]
WantedBy=multi-user.target
"""
HUNTER_FILES = [
    "__init__.py", "config.py", "depth.py", "watchlist.py",
    "filters.py", "writer.py", "evidence.py", "hunter.py",
    "features.py", "tokenizer.py", "fingerprints.py", "afpacket.py"
]

def log(msg, status=None):
    if status == "OK":
        prefix = "[OK]"
    elif status == "FAIL":
        prefix = "[FAIL]"
    elif status == "INFO":
        prefix = "[INFO]"
    elif status == "SKIP":
        prefix = "[SKIP]"
    else:
        prefix = "[....]"
    print(f"{prefix} {msg}", flush=True)


def run_sudo(ssh, command, password, timeout=60, description=None):
    """Run a sudo command, feeding password via stdin."""
    desc = description or command
    full_cmd = f"sudo -S {command}"
    stdin, stdout, stderr = ssh.exec_command(full_cmd, timeout=timeout)
    stdin.write(password + "\n")
    stdin.flush()
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    exit_code = stdout.channel.recv_exit_status()
    # Filter sudo password prompt from stderr
    err_clean = "\n".join(
        line for line in err.splitlines()
        if not line.strip().startswith("[sudo]") and "password for" not in line.lower()
    ).strip()
    if exit_code == 0:
        log(desc, "OK")
        if out:
            print(f"       stdout: {out[:300]}")
    else:
        log(f"{desc} (exit={exit_code})", "FAIL")
        if err_clean:
            print(f"       stderr: {err_clean[:500]}")
        if out:
            print(f"       stdout: {out[:300]}")
    return exit_code, out, err_clean


def run_cmd(ssh, command, timeout=30, description=None):
    """Run a non-sudo command."""
    desc = description or command
    stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    exit_code = stdout.channel.recv_exit_status()
    if exit_code == 0:
        log(desc, "OK")
        if out:
            print(f"       stdout: {out[:300]}")
    else:
        log(f"{desc} (exit={exit_code})", "FAIL")
        if err:
            print(f"       stderr: {err[:500]}")
    return exit_code, out, err


def sftp_upload(sftp, local_path, remote_path, description=None):
    """Upload a file via SFTP."""
    desc = description or f"Upload {os.path.basename(local_path)} -> {remote_path}"
    try:
        sftp.put(local_path, remote_path)
        log(desc, "OK")
        return True
    except Exception as e:
        log(f"{desc}: {e}", "FAIL")
        return False


def main():
    print("=" * 60)
    print("DFI2 Hunter Deployment to AIO (192.168.0.113:2222)")
    print("=" * 60)
    print()

    # Connect
    log(f"Connecting to {HOST}:{PORT} as {USER}", "INFO")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(HOST, port=PORT, username=USER, password=PASSWORD, timeout=30)
        log("SSH connection established", "OK")
    except Exception as e:
        log(f"SSH connection failed: {e}", "FAIL")
        sys.exit(1)

    sftp = ssh.open_sftp()
    log("SFTP session opened", "OK")
    print()

    # -------------------------------------------------------
    # Step 1: Create remote directories
    # -------------------------------------------------------
    print("--- Step 1: Create remote directories ---")
    run_sudo(ssh, "mkdir -p /opt/dfi2/hunter /opt/dfi-hunter /tmp/dfi2_schema",
             PASSWORD, description="mkdir -p /opt/dfi2/hunter /opt/dfi-hunter /tmp/dfi2_schema")
    # Make hunter dir writable by current user for SFTP
    run_sudo(ssh, f"chown -R {USER}:{USER} /opt/dfi2",
             PASSWORD, description=f"chown {USER} /opt/dfi2")
    print()

    # -------------------------------------------------------
    # Step 2: Upload hunter Python files
    # -------------------------------------------------------
    print("--- Step 2: Upload hunter Python files to /opt/dfi2/hunter/ ---")
    failed_uploads = []
    for fname in HUNTER_FILES:
        local = os.path.join(SRC_BASE, "hunter", fname)
        remote = f"/opt/dfi2/hunter/{fname}"
        if os.path.exists(local):
            ok = sftp_upload(sftp, local, remote, f"Upload hunter/{fname}")
            if not ok:
                failed_uploads.append(fname)
        else:
            log(f"LOCAL FILE MISSING: hunter/{fname}", "FAIL")
            failed_uploads.append(fname)

    if failed_uploads:
        log(f"Failed uploads: {failed_uploads}", "FAIL")
    else:
        log("All hunter files uploaded successfully", "OK")
    print()

    # -------------------------------------------------------
    # Step 3: Upload schema file
    # -------------------------------------------------------
    print("--- Step 3: Upload schema/03_buffers.sql ---")
    schema_local = os.path.join(SRC_BASE, "schema", "03_buffers.sql")
    schema_remote = "/tmp/dfi2_schema/03_buffers.sql"
    sftp_upload(sftp, schema_local, schema_remote, "Upload schema/03_buffers.sql -> /tmp/dfi2_schema/")
    print()

    # -------------------------------------------------------
    # Step 4: Apply schema to ClickHouse
    # -------------------------------------------------------
    print("--- Step 4: Apply schema to ClickHouse ---")
    run_sudo(ssh, f"clickhouse-client --multiquery < {schema_remote}",
             PASSWORD, timeout=120,
             description="clickhouse-client --multiquery < 03_buffers.sql")
    print()

    # -------------------------------------------------------
    # Step 5: Service management
    # -------------------------------------------------------
    print("--- Step 5: dfi-hunter2 service management ---")
    # Check if service exists
    rc_exists, out_exists, _ = run_cmd(
        ssh,
        "systemctl list-unit-files dfi-hunter2.service --no-legend | grep dfi-hunter2",
        timeout=15,
        description="Check if dfi-hunter2.service exists"
    )
    service_exists = rc_exists == 0 and "dfi-hunter2" in out_exists

    if service_exists:
        log("Service dfi-hunter2 found — restarting", "INFO")
        run_sudo(ssh, "systemctl restart dfi-hunter2",
                 PASSWORD, timeout=60,
                 description="systemctl restart dfi-hunter2")
        # Brief pause then check status
        time.sleep(2)
        run_cmd(ssh, "systemctl is-active dfi-hunter2",
                timeout=10, description="Check dfi-hunter2 is-active")
    else:
        log("Service dfi-hunter2 NOT found — installing from deploy/", "INFO")

        # Upload service file
        service_local = os.path.join(SRC_BASE, "deploy", "dfi-hunter2.service")
        service_remote_tmp = "/tmp/dfi-hunter2.service"
        sftp_upload(sftp, service_local, service_remote_tmp, "Upload dfi-hunter2.service -> /tmp/")

        # Install service
        run_sudo(ssh, f"cp {service_remote_tmp} /etc/systemd/system/dfi-hunter2.service",
                 PASSWORD, description="cp dfi-hunter2.service -> /etc/systemd/system/")
        run_sudo(ssh, "systemctl daemon-reload",
                 PASSWORD, description="systemctl daemon-reload")
        log("Service installed but NOT started (env file may need configuration)", "INFO")
    print()

    # -------------------------------------------------------
    # Step 6: Upload env2.example
    # -------------------------------------------------------
    print("--- Step 6: Upload env2.example ---")
    env_local = os.path.join(SRC_BASE, "deploy", "env2.example")
    env_remote_tmp = "/tmp/env2.example"
    sftp_upload(sftp, env_local, env_remote_tmp, "Upload env2.example -> /tmp/env2.example")
    print()

    # -------------------------------------------------------
    # Step 7: Install env2 if /etc/dfi-hunter/env2 doesn't exist
    # -------------------------------------------------------
    print("--- Step 7: Install /etc/dfi-hunter/env2 (if not present) ---")
    rc_env, out_env, _ = run_cmd(
        ssh, "test -f /etc/dfi-hunter/env2 && echo EXISTS || echo MISSING",
        timeout=10, description="Check /etc/dfi-hunter/env2 existence"
    )
    env_exists = "EXISTS" in out_env

    if env_exists:
        log("/etc/dfi-hunter/env2 already exists — skipping (not overwriting)", "SKIP")
    else:
        log("/etc/dfi-hunter/env2 not found — installing from env2.example", "INFO")
        run_sudo(ssh, "mkdir -p /etc/dfi-hunter",
                 PASSWORD, description="mkdir -p /etc/dfi-hunter")
        run_sudo(ssh, f"cp {env_remote_tmp} /etc/dfi-hunter/env2",
                 PASSWORD, description="cp env2.example -> /etc/dfi-hunter/env2")
        run_sudo(ssh, "chmod 600 /etc/dfi-hunter/env2",
                 PASSWORD, description="chmod 600 /etc/dfi-hunter/env2")
    print()

    # -------------------------------------------------------
    # Step 8: DO NOT FORGET OFFLOAD! — Disable NIC offloads on capture interface
    # -------------------------------------------------------
    print("--- Step 8: DO NOT FORGET OFFLOAD! Disable NIC offloads ---")
    # Disable offloads immediately
    run_sudo(ssh, f"ethtool -K {CAPTURE_IFACE} gro off gso off tso off lro off sg off tx off rx off 2>/dev/null || true",
             PASSWORD, description=f"ethtool -K {CAPTURE_IFACE} gro/gso/tso/lro/sg/tx/rx off")

    # Install persistent systemd service so offloads stay off across reboots
    offload_svc_remote = "/tmp/dfi-nic-offload.service"
    try:
        with sftp.file(offload_svc_remote, 'w') as f:
            f.write(NIC_OFFLOAD_SERVICE)
        log("Wrote dfi-nic-offload.service", "OK")
    except Exception as e:
        log(f"Write offload service: {e}", "FAIL")

    run_sudo(ssh, f"cp {offload_svc_remote} /etc/systemd/system/dfi-nic-offload.service",
             PASSWORD, description="Install dfi-nic-offload.service")
    run_sudo(ssh, "systemctl daemon-reload && systemctl enable dfi-nic-offload",
             PASSWORD, description="Enable dfi-nic-offload.service (persistent)")

    # Verify offloads are off
    rc, out, _ = run_sudo(ssh,
                          f"ethtool -k {CAPTURE_IFACE} | grep -E 'generic-receive-offload|tcp-segmentation-offload|generic-segmentation-offload|large-receive-offload'",
                          PASSWORD, description=f"Verify offloads off on {CAPTURE_IFACE}")
    if out:
        print(f"       {out}")
    print()

    # -------------------------------------------------------
    # Summary
    # -------------------------------------------------------
    print("=" * 60)
    print("Deployment complete.")
    if not service_exists:
        print()
        print("NOTE: dfi-hunter2 service was installed but NOT started.")
        print("      Review /etc/dfi-hunter/env2, then run:")
        print("      sudo systemctl start dfi-hunter2")
        print("      sudo systemctl enable dfi-hunter2")
    print("=" * 60)

    sftp.close()
    ssh.close()


if __name__ == "__main__":
    main()
