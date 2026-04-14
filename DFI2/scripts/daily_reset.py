#!/usr/bin/env python3
"""
daily_reset.py — Daily honeypot VM rollback + password randomization
====================================================================
Runs on Proxmox host. Rolls back all 10 VMs to a known-good snapshot
and changes all user passwords to random disposable strings.

NOTE: Must snap back to access, random password not remembered!

Usage:
  python3 /opt/dfi_edge/daily_reset.py              # Full reset, 10-min stagger
  python3 /opt/dfi_edge/daily_reset.py --vm 106      # Single VM, no stagger
  python3 /opt/dfi_edge/daily_reset.py --dry-run     # Show plan only
  python3 /opt/dfi_edge/daily_reset.py --snapshot X   # Override snapshot name
"""
import subprocess
import secrets
import argparse
import json
import time
import sys
import os
from datetime import datetime

# Ensure /usr/sbin is in PATH (qm lives there, cron.d jobs have minimal PATH)
if "/usr/sbin" not in os.environ.get("PATH", ""):
    os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Safe charset: no ' " $ \ ` ; & | < > (avoids shell/PS quoting issues)
SAFE_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^*-_=+:.?~"

DEFAULT_SNAPSHOT = "dfi_baseline_8c4g"

VM_ORDER = [
    # (vmid, name, os_type, snapshot_override)
    (100, "UBT20",  "linux",   "WORK"),
    (101, "UBT22",  "linux",   None),
    (102, "UBT24",  "linux",   None),
    (103, "SRV19",  "windows", None),
    (104, "SRV22",  "windows", None),
    (105, "SRV25",  "windows", None),
    (106, "WIN10",  "windows", None),
    (107, "SQL19",  "windows", None),
    (108, "SQL22",  "windows", None),
    (109, "SQL25",  "windows", None),
    # Honeypot Farm (216.126.0.128/26) — added 2026-03-16
    (111, "INTRANET",     "linux",   "pusher_removed_2026-04-10"),
    (113, "HR-DB",        "linux",   "pusher_removed_2026-04-10"),
    (114, "FILESERV",     "linux",   "pusher_removed_2026-04-10"),
    (115, "NS1",          "linux",   "pusher_removed_2026-04-10"),
    (116, "CORPMAIL",     "linux",   "pusher_removed_2026-04-10"),
    (117, "PAYROLL-DB",   "linux",   "pusher_removed_2026-04-10"),
    (118, "CACHE01",      "linux",   "pusher_removed_2026-04-10"),
    (119, "APPDATA",      "linux",   "pusher_removed_2026-04-10"),
    (120, "LEGACY-GW",    "linux",   "pusher_removed_2026-04-10"),
    (121, "DEV-WKS",      "linux",   "pusher_removed_2026-04-10"),
    (122, "LOGSERVER",    "linux",   "pusher_removed_2026-04-10"),
    (123, "CI-BUILD",     "linux",   "pusher_removed_2026-04-10"),
    (124, "VOIP-PBX",     "linux",   "pusher_removed_2026-04-10"),
    (125, "CORP-DC",      "linux",   "pusher_removed_2026-04-10"),
    (126, "WIN-8KF3M2DPR91", "windows", "farm_rebuilt_2026-03-26"),
]

LXC_ORDER = [
    (110, "this-is-a-trap", "pusher_removed_2026-04-10"),
    (112, "meshcentral", "audited_2026-04-02"),
    (127, "hp-208-2", "pusher_removed_2026-04-10"),
    (128, "hp-208-3", "pusher_removed_2026-04-10"),
    (129, "hp-208-4", "pusher_removed_2026-04-10"),
    (130, "hp-208-5", "pusher_removed_2026-04-10"),
    (131, "hp-208-6", "pusher_removed_2026-04-10"),
    (132, "hp-208-7", "pusher_removed_2026-04-10"),
    (133, "hp-208-8", "pusher_removed_2026-04-10"),
    (134, "hp-208-9", "pusher_removed_2026-04-10"),
    (135, "hp-208-10", "pusher_removed_2026-04-10"),
    (136, "hp-208-11", "pusher_removed_2026-04-10"),
    (137, "hp-208-12", "pusher_removed_2026-04-10"),
    (138, "hp-208-13", "pusher_removed_2026-04-10"),
    (139, "hp-208-14", "pusher_removed_2026-04-10"),
    (140, "hp-208-15", "pusher_removed_2026-04-10"),
    (141, "hp-208-16", "pusher_removed_2026-04-10"),
    (142, "hp-208-17", "pusher_removed_2026-04-10"),
    (143, "hp-208-18", "pusher_removed_2026-04-10"),
    (144, "hp-208-19", "pusher_removed_2026-04-10"),
    (145, "hp-208-20", "pusher_removed_2026-04-10"),
    (146, "hp-208-21", "pusher_removed_2026-04-10"),
    (147, "hp-208-22", "pusher_removed_2026-04-10"),
    (148, "hp-208-23", "pusher_removed_2026-04-10"),
    (149, "hp-208-24", "pusher_removed_2026-04-10"),
    (150, "hp-208-25", "pusher_removed_2026-04-10"),
    (151, "hp-208-26", "pusher_removed_2026-04-10"),
    (152, "hp-208-27", "pusher_removed_2026-04-10"),
    (153, "hp-208-28", "pusher_removed_2026-04-10"),
    (154, "hp-208-29", "pusher_removed_2026-04-10"),
    (155, "hp-208-30", "pusher_removed_2026-04-10"),
    (156, "hp-208-31", "pusher_removed_2026-04-10"),
    (157, "hp-208-32", "pusher_removed_2026-04-10"),
    (158, "hp-208-33", "pusher_removed_2026-04-10"),
    (159, "hp-208-34", "pusher_removed_2026-04-10"),
    (160, "hp-208-35", "pusher_removed_2026-04-10"),
    (161, "hp-208-36", "pusher_removed_2026-04-10"),
    (162, "hp-208-37", "pusher_removed_2026-04-10"),
]

LINUX_USERS = ["colo8gent"]
WINDOWS_USERS = ["Administrator", "colo8gent"]

STAGGER_SECONDS = 60    # 60 seconds between VMs (~10 min total for 10 VMs)
STOP_TIMEOUT = 120       # seconds to wait for VM to stop
AGENT_TIMEOUT = 180      # seconds to wait for guest agent

LOG_DIR = "/opt/dfi_edge/logs"


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)


def run_cmd(cmd, timeout=60):
    """Run a command, return (rc, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return -1, "", str(e)


def gen_password(length=32):
    return "".join(secrets.choice(SAFE_CHARS) for _ in range(length))


def wait_stopped(vmid, timeout=STOP_TIMEOUT):
    """Poll qm status until VM is stopped."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc, out, _ = run_cmd(["qm", "status", str(vmid)], timeout=10)
        if "stopped" in out.lower():
            return True
        time.sleep(3)
    return False


def wait_agent(vmid, timeout=AGENT_TIMEOUT):
    """Poll qm agent ping until guest agent responds."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc, _, _ = run_cmd(["qm", "agent", str(vmid), "ping"], timeout=10)
        if rc == 0:
            return True
        time.sleep(5)
    return False


def qm_guest_exec(vmid, program, args, timeout=15):
    """Run command inside guest via QEMU agent. Returns (success, output)."""
    cmd = ["qm", "guest", "exec", str(vmid), "--timeout", str(timeout),
           "--", program] + args
    rc, out, err = run_cmd(cmd, timeout=timeout + 15)
    if rc != 0:
        return False, err or out
    try:
        result = json.loads(out)
        exitcode = result.get("exitcode", -1)
        out_data = result.get("out-data", "")
        err_data = result.get("err-data", "")
        if exitcode == 0:
            return True, out_data
        return False, err_data or out_data or f"exitcode={exitcode}"
    except (json.JSONDecodeError, ValueError):
        return rc == 0, out


def change_linux_password(vmid, user, password):
    """Change password on a Linux VM via qm guest exec."""
    return qm_guest_exec(vmid, "/bin/bash", [
        "-c", f"echo '{user}:{password}' | chpasswd"
    ])


def change_windows_password(vmid, user, password):
    """Change password on a Windows VM via qm guest exec."""
    ps_cmd = (
        f"Set-LocalUser -Name '{user}' "
        f"-Password (ConvertTo-SecureString '{password}' -AsPlainText -Force)"
    )
    return qm_guest_exec(vmid, "powershell.exe", ["-NoProfile", "-Command", ps_cmd])


def reset_vm(vmid, name, os_type, snapshot, dry_run=False):
    """Full reset sequence for one VM. Returns True on success."""
    log(f"--- {name} (VM {vmid}, {os_type}) ---")

    if dry_run:
        users = LINUX_USERS if os_type == "linux" else WINDOWS_USERS
        log(f"  DRY-RUN: stop -> rollback '{snapshot}' -> start -> change pw for {users}")
        return True

    # Step 1: Stop VM
    log(f"  Stopping VM {vmid}...")
    rc, out, err = run_cmd(["qm", "stop", str(vmid)], timeout=30)
    if rc != 0:
        log(f"  WARN: qm stop rc={rc}: {err or out}")
    if not wait_stopped(vmid):
        log(f"  FAIL: VM {vmid} did not stop within {STOP_TIMEOUT}s -- skipping")
        return False
    log(f"  VM {vmid} stopped")

    # Step 2: Rollback snapshot
    log(f"  Rolling back to '{snapshot}'...")
    rc, _, err = run_cmd(["qm", "rollback", str(vmid), snapshot], timeout=60)
    if rc != 0:
        log(f"  FAIL: Rollback failed (rc={rc}): {err} -- skipping (NOT starting VM)")
        return False
    log(f"  Rollback OK")

    # Step 3: Start VM
    log(f"  Starting VM {vmid}...")
    rc, _, err = run_cmd(["qm", "start", str(vmid)], timeout=30)
    if rc != 0:
        log(f"  FAIL: Start failed (rc={rc}): {err}")
        return False

    # Step 4: Wait for guest agent
    log(f"  Waiting for guest agent...")
    if not wait_agent(vmid):
        log(f"  WARN: Agent not responding after {AGENT_TIMEOUT}s -- skipping password change")
        return True  # VM is running, just can't change passwords

    log(f"  Agent responding")

    # Step 5: Change passwords
    if os_type == "linux":
        users = LINUX_USERS
        change_fn = change_linux_password
    else:
        users = WINDOWS_USERS
        change_fn = change_windows_password

    pw_ok = True
    for user in users:
        pw = gen_password()
        ok, detail = change_fn(vmid, user, pw)
        if ok:
            log(f"  Password changed: {user} -> [random 32-char]")
        else:
            log(f"  WARN: Password change failed for {user}: {detail}")
            pw_ok = False

    return pw_ok


def reset_lxc(vmid, name, snapshot, dry_run=False):
    log(f"--- {name} (CT {vmid}, LXC) ---")
    if dry_run:
        log(f"  DRY-RUN: pct stop -> rollback '{snapshot}' -> start")
        return True
    log(f"  Stopping CT {vmid}...")
    run_cmd(["pct", "stop", str(vmid)], timeout=60)
    import time as _t; _t.sleep(3)
    log(f"  Rolling back to '{snapshot}'...")
    rc, _, err = run_cmd(["pct", "rollback", str(vmid), snapshot], timeout=120)
    if rc != 0:
        log(f"  FAIL: Rollback failed: {err}")
        return False
    log(f"  Starting CT {vmid}...")
    rc, _, err = run_cmd(["pct", "start", str(vmid)], timeout=120)
    if rc != 0:
        log(f"  FAIL: Start failed: {err}")
        return False
    log(f"  CT {vmid} reset OK")
    return True


def main():
    parser = argparse.ArgumentParser(description="Daily honeypot VM reset")
    parser.add_argument("--vm", type=int, help="Reset single VM by ID (no stagger)")
    parser.add_argument("--dry-run", action="store_true", help="Show plan, do nothing")
    parser.add_argument("--snapshot", default=None,
                        help="Snapshot name override for all VMs (default: per-VM or dfi_baseline_8c4g)")
    args = parser.parse_args()

    os.makedirs(LOG_DIR, exist_ok=True)

    log("=" * 60)
    log("Daily honeypot VM reset starting")
    log(f"  Snapshot: {args.snapshot or 'per-VM defaults'}")
    log(f"  Mode: {'DRY-RUN' if args.dry_run else 'LIVE'}")
    if args.vm:
        log(f"  Target: VM {args.vm} only")
    log("=" * 60)

    # Filter VM list
    if args.vm:
        vms = [(vmid, name, ost, snap) for vmid, name, ost, snap in VM_ORDER if vmid == args.vm]
        if not vms:
            log(f"ERROR: VM {args.vm} not in inventory")
            sys.exit(1)
    else:
        vms = VM_ORDER

    results = {}
    for i, (vmid, name, os_type, snap_override) in enumerate(vms):
        # Stagger: 60s between VMs (skip for first VM, single-VM mode, or dry-run)
        if i > 0 and not args.vm and not args.dry_run:
            log(f"  Stagger: waiting {STAGGER_SECONDS}s before next VM...")
            time.sleep(STAGGER_SECONDS)

        snapshot = args.snapshot or snap_override or DEFAULT_SNAPSHOT
        try:
            ok = reset_vm(vmid, name, os_type, snapshot, args.dry_run)
            results[f"{name}({vmid})"] = "OK" if ok else "FAIL"
        except Exception as e:
            log(f"  ERROR: {name}({vmid}): {e}")
            results[f"{name}({vmid})"] = "ERROR"

    # Summary
    log("")
    log("=" * 60)
    # Reset LXC containers
    if not args.vm:
        for vmid, name, snap in LXC_ORDER:
            ok = reset_lxc(vmid, name, snap, args.dry_run)
            results[f"{name}({vmid})"] = "OK" if ok else "FAIL"

    log("SUMMARY")
    log("=" * 60)
    for vm_label, status in results.items():
        log(f"  {vm_label}: {status}")

    failed = sum(1 for s in results.values() if s != "OK")
    log(f"\nTotal: {len(results)} VMs, {len(results) - failed} OK, {failed} failed")
    log("Daily reset complete")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
