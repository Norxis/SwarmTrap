#!/usr/bin/env python3
"""
test_meshcentral.py — Test MeshCentral connectivity and command execution
via PV1 (192.168.0.100) -> CT 112 -> MeshCentral -> Windows target.

Steps:
  1. Connect to PV1 via Paramiko
  2. List devices, extract first node ID
  3. Run test commands on the Windows box (hostname, ipconfig, dir, sc query)
  4. Try both with and without --powershell flag
"""

import paramiko
import json
import time
import sys
import re


PV1_HOST = "192.168.0.100"
PV1_PORT = 22
PV1_USER = "root"
PV1_PASS = "CHANGE_ME"

MESHCTRL = "/opt/meshcentral/node_modules/meshcentral/meshctrl.js"
MESH_URL = "wss://localhost"
MESH_USER = "admin"
MESH_PASS = "CHANGE_ME"

# Base command prefix executed inside CT 112
MESHCTRL_BASE = (
    f'pct exec 112 -- node {MESHCTRL}'
    f' --url {MESH_URL}'
    f' --loginuser {MESH_USER}'
    f' --loginpass "{MESH_PASS}"'
)


def ssh_connect():
    """Connect to PV1 via Paramiko."""
    print(f"[*] Connecting to PV1 ({PV1_HOST}:{PV1_PORT})...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(PV1_HOST, port=PV1_PORT, username=PV1_USER, password=PV1_PASS, timeout=15)
    print("[+] Connected to PV1.")
    return client


def run_cmd(client, cmd, timeout=30):
    """Execute a command on PV1 and return (stdout, stderr, exit_code)."""
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return out, err, exit_code


def get_device_node_id(client):
    """List MeshCentral devices and return the _id of the first device."""
    print("\n" + "=" * 70)
    print("[*] Step 2: Listing MeshCentral devices...")
    print("=" * 70)

    cmd = f'{MESHCTRL_BASE} listdevices --json 2>&1'
    print(f"[>] CMD: {cmd[:150]}...")
    out, err, rc = run_cmd(client, cmd, timeout=30)

    print(f"[<] Exit code: {rc}")
    if err.strip():
        print(f"[<] STDERR:\n{err.strip()}")
    print(f"[<] STDOUT ({len(out)} bytes):\n{out[:2000]}")

    # Try to parse JSON from stdout
    node_id = None
    json_data = None

    # Try to find JSON array in the output
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("[") or line.startswith("{"):
            try:
                json_data = json.loads(line)
                break
            except json.JSONDecodeError:
                continue

    # If single-line parse failed, try the entire output
    if json_data is None:
        match = re.search(r'(\[.*\])', out, re.DOTALL)
        if match:
            try:
                json_data = json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

    if json_data is None:
        match = re.search(r'(\{.*\})', out, re.DOTALL)
        if match:
            try:
                json_data = json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

    if json_data is not None:
        if isinstance(json_data, list) and len(json_data) > 0:
            device = json_data[0]
            node_id = device.get("_id", None)
            device_name = device.get("name", "unknown")
            print(f"\n[+] Found device: {device_name}")
            print(f"[+] Node ID: {node_id}")
            print(f"[+] Full device record:\n{json.dumps(device, indent=2)[:1000]}")
        elif isinstance(json_data, dict):
            if "_id" in json_data:
                node_id = json_data["_id"]
                print(f"[+] Node ID: {node_id}")
            else:
                for key, val in json_data.items():
                    if isinstance(val, dict) and "_id" in val:
                        node_id = val["_id"]
                        print(f"[+] Node ID: {node_id}")
                        break
                    elif isinstance(val, list) and len(val) > 0:
                        node_id = val[0].get("_id", None)
                        print(f"[+] Node ID: {node_id}")
                        break
    else:
        print("[!] Could not parse JSON from output.")
        print("[!] Will attempt to extract node ID from raw text...")
        match = re.search(r'(node//[^\s"]+)', out)
        if match:
            node_id = match.group(1)
            print(f"[+] Extracted node ID from text: {node_id}")

    if node_id is None:
        print("[!] FAILED to get device node ID.")
        print("[!] Cannot proceed with command tests.")
        sys.exit(1)

    return node_id


def run_mesh_command(client, node_id, run_cmd_str, label, use_powershell=False, wait=5):
    """Run a command on the Windows box via MeshCentral."""
    ps_flag = " --powershell" if use_powershell else ""
    mode_label = "PowerShell" if use_powershell else "CMD"

    cmd = (
        f'{MESHCTRL_BASE} runcommand'
        f' --id "{node_id}"'
        f' --run "{run_cmd_str}"'
        f'{ps_flag}'
        f' 2>&1'
    )

    print(f"\n--- {label} [{mode_label}] ---")
    print(f"[>] CMD: {cmd[:250]}...")
    out, err, rc = run_cmd(client, cmd, timeout=30)

    print(f"[<] Exit code: {rc}")
    if err.strip():
        print(f"[<] STDERR:\n{err.strip()}")
    print(f"[<] STDOUT:\n{out.strip() if out.strip() else '(empty)'}")

    print(f"[*] Waiting {wait}s for async output...")
    time.sleep(wait)

    return out, err, rc


def test_commands(client, node_id):
    """Run test commands on the Windows target via MeshCentral."""
    print("\n" + "=" * 70)
    print("[*] Step 3: Testing commands on Windows target")
    print(f"[*] Node ID: {node_id}")
    print("=" * 70)

    # Define test commands: (label, command_string)
    test_cases = [
        ("3a. hostname", "hostname"),
        ("3b. ipconfig", "ipconfig"),
        ('3c. dir DFI directory', 'dir \\"C:\\\\Program Files\\\\DFI\\\\agent\\\\dfi_agent\\"'),
        ("3d. sc query WinHuntAgent", "sc query WinHuntAgent"),
    ]

    results = {}

    # Run each command without --powershell first
    print("\n" + "=" * 70)
    print("[*] Phase A: Running commands WITHOUT --powershell flag")
    print("=" * 70)

    for label, cmd_str in test_cases:
        out, err, rc = run_mesh_command(client, node_id, cmd_str, label, use_powershell=False, wait=4)
        results[f"{label}_cmd"] = (out, err, rc)

    # Now try with --powershell
    print("\n" + "=" * 70)
    print("[*] Phase B: Running commands WITH --powershell flag")
    print("=" * 70)

    ps_test_cases = [
        ("3a-ps. hostname", "hostname"),
        ("3b-ps. ipconfig findstr", "ipconfig | findstr IPv4"),
        ('3c-ps. dir DFI directory', 'Get-ChildItem \\"C:\\\\Program Files\\\\DFI\\\\agent\\\\dfi_agent\\"'),
        ("3d-ps. sc query WinHuntAgent", "sc.exe query WinHuntAgent"),
    ]

    for label, cmd_str in ps_test_cases:
        out, err, rc = run_mesh_command(client, node_id, cmd_str, label, use_powershell=True, wait=4)
        results[f"{label}_ps"] = (out, err, rc)

    # Combined PowerShell command
    print("\n" + "=" * 70)
    print("[*] Phase C: Combined PowerShell command")
    print("=" * 70)

    combined_cmd = 'hostname; ipconfig | findstr IPv4'
    out, err, rc = run_mesh_command(
        client, node_id, combined_cmd,
        "Combined: hostname + ipconfig",
        use_powershell=True, wait=5
    )
    results["combined_ps"] = (out, err, rc)

    return results


def main():
    print("=" * 70)
    print("  MeshCentral Connectivity & Command Test")
    print(f"  Target: PV1 ({PV1_HOST}) -> CT 112 -> MeshCentral -> Windows")
    print("=" * 70)

    client = None
    try:
        # Step 1: Connect to PV1
        client = ssh_connect()

        # Quick check: is CT 112 running?
        print("\n[*] Checking CT 112 status...")
        out, err, rc = run_cmd(client, "pct status 112 2>&1")
        print(f"[<] CT 112 status: {out.strip()}")
        if "running" not in out.lower():
            print("[!] WARNING: CT 112 may not be running!")

        # Step 2: Get device node ID
        node_id = get_device_node_id(client)

        # Step 3: Test commands
        results = test_commands(client, node_id)

        # Summary
        print("\n" + "=" * 70)
        print("  SUMMARY")
        print("=" * 70)
        for key, (out, err, rc) in results.items():
            has_output = bool(out.strip())
            print(f"  {key:40s} | exit={rc} | output={'YES' if has_output else 'NO'} | {out.strip()[:60]}")

    except Exception as e:
        print(f"\n[!] ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if client:
            client.close()
            print("\n[*] SSH connection closed.")

    print("\n[+] Test complete.")


if __name__ == "__main__":
    main()
