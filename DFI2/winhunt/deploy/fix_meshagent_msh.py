#!/usr/bin/env python3
"""
fix_meshagent_msh.py - Fix MeshAgent MSH configuration on Windows target.

Steps:
1. Connect to PV1 via paramiko
2. Get full mesh ID from meshctrl (JSON)
3. Read current MSH from Windows via WinRM
4. Download agent + MSH from MeshCentral via curl on CT112
5. Serve MSH via HTTP from CT112
6. Download proper MSH to Windows via WinRM, restart agent
7. Verify device appears in MeshCentral
"""

import paramiko
import json
import time
import sys
import urllib.parse
import winrm
import re

# ── Config ────────────────────────────────────────────────────────────
PV1_HOST = "192.168.0.100"
PV1_USER = "root"
PV1_PASS = "CHANGE_ME"

WIN_HOST = "172.16.3.160"
WIN_USER = "Administrator"
WIN_PASS = "CHANGE_ME"

CT112_IP = "172.16.3.112"

MESHCTRL = "node /opt/meshcentral/node_modules/meshcentral/meshctrl.js"
MESH_AUTH = '--url wss://localhost --loginuser admin --loginpass "CHANGE_ME"'


def ssh_exec(ssh, cmd, label="", timeout=30):
    """Execute command via SSH and return stdout/stderr."""
    print(f"\n{'='*70}")
    if label:
        print(f"[{label}]")
    print(f"CMD: {cmd[:200]}{'...' if len(cmd)>200 else ''}")
    print("-" * 70)
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if out.strip():
        print(f"STDOUT:\n{out}")
    if err.strip():
        print(f"STDERR:\n{err}")
    if not out.strip() and not err.strip():
        print("(no output)")
    return out, err


def winrm_exec(ps_script, label=""):
    """Execute PowerShell on Windows target via WinRM."""
    print(f"\n{'='*70}")
    if label:
        print(f"[WinRM: {label}]")
    print(f"PS:\n{ps_script[:500]}{'...' if len(ps_script)>500 else ''}")
    print("-" * 70)
    session = winrm.Session(
        f"http://{WIN_HOST}:5985/wsman",
        auth=(WIN_USER, WIN_PASS),
        transport="ntlm",
        server_cert_validation="ignore",
    )
    result = session.run_ps(ps_script)
    out = result.std_out.decode("utf-8", errors="replace")
    err = result.std_err.decode("utf-8", errors="replace")
    if out.strip():
        print(f"STDOUT:\n{out}")
    if err.strip():
        print(f"STDERR:\n{err}")
    if not out.strip() and not err.strip():
        print("(no output)")
    return out, err


def main():
    # ── Step 1: Connect to PV1 ───────────────────────────────────────
    print("\n" + "#" * 70)
    print("# STEP 1: Connect to PV1 via Paramiko")
    print("#" * 70)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(PV1_HOST, port=22, username=PV1_USER, password=PV1_PASS, timeout=15)
    print(f"Connected to {PV1_HOST} as {PV1_USER}")

    # ── Step 2: Get full mesh ID ─────────────────────────────────────
    print("\n" + "#" * 70)
    print("# STEP 2: Get full mesh ID from meshctrl (JSON)")
    print("#" * 70)
    cmd = f'pct exec 112 -- {MESHCTRL} {MESH_AUTH} listdevicegroups --json 2>&1'
    out, err = ssh_exec(ssh, cmd, "listdevicegroups --json")

    # Parse JSON - output might have non-JSON prefix lines
    mesh_id = None
    mesh_name = None
    # Try to find JSON array in output
    json_match = re.search(r'(\[.*\])', out, re.DOTALL)
    if json_match:
        try:
            groups = json.loads(json_match.group(1))
            if groups:
                mesh_id = groups[0].get("_id", "")
                mesh_name = groups[0].get("name", "")
                print(f"\nParsed mesh ID: {mesh_id}")
                print(f"Parsed mesh name: {mesh_name}")
                print(f"Full group data: {json.dumps(groups[0], indent=2)}")
        except json.JSONDecodeError as e:
            print(f"JSON parse error: {e}")

    if not mesh_id:
        # Try parsing the whole output as JSON
        try:
            groups = json.loads(out.strip())
            if groups:
                mesh_id = groups[0].get("_id", "")
                mesh_name = groups[0].get("name", "")
                print(f"\nParsed mesh ID: {mesh_id}")
                print(f"Parsed mesh name: {mesh_name}")
        except json.JSONDecodeError:
            print("ERROR: Could not parse mesh ID from output")
            print("Trying non-JSON fallback...")
            # Try without --json
            cmd2 = f'pct exec 112 -- {MESHCTRL} {MESH_AUTH} listdevicegroups 2>&1'
            out2, _ = ssh_exec(ssh, cmd2, "listdevicegroups (no --json)")

    if not mesh_id:
        print("FATAL: Could not determine mesh ID. Exiting.")
        ssh.close()
        sys.exit(1)

    # ── Step 3: Read current MSH from Windows ────────────────────────
    print("\n" + "#" * 70)
    print("# STEP 3: Read current MSH file from Windows via WinRM")
    print("#" * 70)
    ps_read_msh = 'Get-Content "C:\\Program Files\\Mesh Agent\\MeshAgent.msh"'
    winrm_exec(ps_read_msh, "Read current MeshAgent.msh")

    # ── Step 4: Download agent + MSH from MeshCentral ────────────────
    print("\n" + "#" * 70)
    print("# STEP 4: Download agent and MSH from MeshCentral on CT112")
    print("#" * 70)

    # URL-encode the mesh ID
    mesh_id_encoded = urllib.parse.quote(mesh_id, safe="")
    print(f"Raw mesh ID: {mesh_id}")
    print(f"URL-encoded mesh ID: {mesh_id_encoded}")

    # 4a: Download configured agent with embedded MSH
    # Use single quotes in the bash command to prevent $ expansion
    agent_url = f"https://localhost/meshagents?id=4&meshid={mesh_id_encoded}&installflags=0"
    # Escape any single quotes in the URL (unlikely but safe)
    agent_url_escaped = agent_url.replace("'", "'\\''")
    cmd_agent = f"pct exec 112 -- curl -sk '{agent_url_escaped}' -o /tmp/meshagent_configured.exe -w 'size=%{{size_download}}'"
    out_agent, err_agent = ssh_exec(ssh, cmd_agent, "Download configured agent binary", timeout=60)

    # 4b: Check file size
    out_size, _ = ssh_exec(ssh, "pct exec 112 -- ls -la /tmp/meshagent_configured.exe", "Check agent file size")
    # Parse size
    agent_size = 0
    for line in (out_size + (err_agent or "") + (out_agent or "")).split("\n"):
        if "size=" in line:
            try:
                agent_size = int(line.split("size=")[1].strip().split()[0])
            except (ValueError, IndexError):
                pass
    for line in out_size.split("\n"):
        parts = line.split()
        if len(parts) >= 5 and parts[4].isdigit():
            agent_size = max(agent_size, int(parts[4]))

    print(f"\nAgent binary size: {agent_size} bytes ({agent_size/1024/1024:.1f} MB)")
    if agent_size > 3 * 1024 * 1024:
        print("GOOD: Agent binary is > 3MB - likely a real agent with embedded MSH")
    else:
        print("WARNING: Agent binary is < 3MB - may be an error page or empty")

    # 4c: Download MSH settings directly
    msh_url = f"https://localhost/meshsettings?id={mesh_id_encoded}"
    msh_url_escaped = msh_url.replace("'", "'\\''")
    cmd_msh = f"pct exec 112 -- curl -sk '{msh_url_escaped}' -o /tmp/meshagent_proper.msh -w 'size=%{{size_download}}'"
    out_msh, err_msh = ssh_exec(ssh, cmd_msh, "Download MSH settings", timeout=30)

    # 4d: Print the MSH content
    out_msh_content, _ = ssh_exec(ssh, "pct exec 112 -- cat /tmp/meshagent_proper.msh", "Contents of downloaded MSH")

    # Check MSH size
    out_msh_size, _ = ssh_exec(ssh, "pct exec 112 -- ls -la /tmp/meshagent_proper.msh", "MSH file size")

    msh_valid = False
    if "MeshServer" in (out_msh_content or "") or "MeshID" in (out_msh_content or ""):
        print("\nGOOD: Downloaded MSH contains MeshServer/MeshID settings")
        msh_valid = True
    else:
        print("\nWARNING: Downloaded MSH does not look valid")
        # Try alternate URL formats
        print("\nTrying alternate MSH URL formats...")

        # Try with just the hex part of the mesh ID
        # mesh//servername/HEX -> try just HEX
        hex_part = mesh_id.split("/")[-1] if "/" in mesh_id else mesh_id
        alt_urls = [
            f"https://localhost/meshsettings?id={urllib.parse.quote(mesh_id, safe='')}",
            f"https://localhost/meshsettings?id={hex_part}",
        ]
        for i, alt_url in enumerate(alt_urls):
            alt_escaped = alt_url.replace("'", "'\\''")
            cmd_alt = f"pct exec 112 -- curl -sk '{alt_escaped}' -o /tmp/meshagent_alt_{i}.msh -w 'size=%{{size_download}}'"
            ssh_exec(ssh, cmd_alt, f"Alt MSH URL #{i}")
            out_alt, _ = ssh_exec(ssh, f"pct exec 112 -- cat /tmp/meshagent_alt_{i}.msh", f"Alt MSH #{i} contents")
            if "MeshServer" in (out_alt or "") or "MeshID" in (out_alt or ""):
                print(f"SUCCESS: Alt URL #{i} returned valid MSH!")
                # Copy to proper location
                ssh_exec(ssh, f"pct exec 112 -- cp /tmp/meshagent_alt_{i}.msh /tmp/meshagent_proper.msh", "Copy valid MSH")
                msh_valid = True
                out_msh_content = out_alt
                break

    if not msh_valid:
        # Try using meshctrl to get the MSH another way - check if agent config is available
        print("\nTrying to extract MSH from the configured agent binary...")
        # The agent binary has the MSH appended; try strings grep
        cmd_extract = "pct exec 112 -- bash -c \"strings /tmp/meshagent_configured.exe | grep -A 50 'MeshName\\|MeshServer\\|MeshID' | head -60\""
        out_extract, _ = ssh_exec(ssh, cmd_extract, "Extract MSH from agent binary")
        if "MeshServer" in (out_extract or "") or "MeshID" in (out_extract or ""):
            print("Found MSH content in agent binary, extracting...")
            # Extract the MSH section - it's usually at the end of the binary
            cmd_tail = "pct exec 112 -- bash -c \"tail -c 2000 /tmp/meshagent_configured.exe | strings | grep -v '^$' | head -30\""
            out_tail, _ = ssh_exec(ssh, cmd_tail, "Tail of agent binary")

    if not msh_valid:
        print("\n" + "!" * 70)
        print("WARNING: Could not get a valid MSH file from MeshCentral API.")
        print("Will try to construct one manually from the mesh ID.")
        print("!" * 70)

        # Construct MSH manually
        # We need: MeshName, MeshType, MeshID, ServerID, MeshServer
        # Get ServerID from meshcentral config
        out_serverid, _ = ssh_exec(ssh,
            'pct exec 112 -- bash -c "cat /opt/meshcentral/meshcentral-data/meshagent.msh 2>/dev/null || echo NOT_FOUND"',
            "Read server-side MSH template")

        if "NOT_FOUND" not in (out_serverid or ""):
            print("Found server-side MSH template, using it")
            ssh_exec(ssh, "pct exec 112 -- cp /opt/meshcentral/meshcentral-data/meshagent.msh /tmp/meshagent_proper.msh",
                     "Copy server MSH to /tmp")
            out_msh_content, _ = ssh_exec(ssh, "pct exec 112 -- cat /tmp/meshagent_proper.msh", "Server MSH contents")
            if "MeshServer" in (out_msh_content or ""):
                msh_valid = True
        
        if not msh_valid:
            # Try meshcentral-data for the certificate hash
            out_cert, _ = ssh_exec(ssh,
                'pct exec 112 -- bash -c "openssl x509 -in /opt/meshcentral/meshcentral-data/webserver-cert-public.crt -fingerprint -sha384 -noout 2>/dev/null"',
                "Get server cert fingerprint")
            
            # Build minimal MSH
            server_hash = ""
            if "Fingerprint" in (out_cert or ""):
                server_hash = out_cert.split("=", 1)[1].strip().replace(":", "").upper()

            # The MeshID in the MSH is the hex-encoded portion
            msh_meshid = mesh_id
            msh_content = f"""MeshName={mesh_name or 'WinHunt'}
MeshType=2
MeshID={msh_meshid}
ServerID={server_hash}
MeshServer=wss://{CT112_IP}:443/agent.ashx
"""
            print(f"\nConstructed MSH:\n{msh_content}")
            # Write it to CT112
            # Escape for bash
            msh_escaped = msh_content.replace("'", "'\\''")
            ssh_exec(ssh,
                f"pct exec 112 -- bash -c 'cat > /tmp/meshagent_proper.msh << MSHEOF\n{msh_content}MSHEOF'",
                "Write constructed MSH")
            out_msh_content, _ = ssh_exec(ssh, "pct exec 112 -- cat /tmp/meshagent_proper.msh", "Verify constructed MSH")
            msh_valid = True

    # ── Step 5: Serve MSH via HTTP from CT112 ────────────────────────
    print("\n" + "#" * 70)
    print("# STEP 5: Serve files via HTTP from CT112")
    print("#" * 70)

    # Kill old http.server
    ssh_exec(ssh, 'pct exec 112 -- bash -c "pkill -f http.server 2>/dev/null; true"', "Kill old http.server")
    time.sleep(1)

    # Start new http.server
    ssh_exec(ssh,
        'pct exec 112 -- bash -c "setsid python3 -m http.server 8888 --directory /tmp </dev/null >/dev/null 2>&1 & sleep 2 && ss -tlnp | grep 8888"',
        "Start HTTP server on port 8888", timeout=15)

    # Verify files are accessible
    ssh_exec(ssh,
        f'pct exec 112 -- curl -s http://127.0.0.1:8888/meshagent_proper.msh | head -5',
        "Verify MSH accessible via HTTP")

    # ── Step 6: Download MSH to Windows and restart agent ─────────────
    print("\n" + "#" * 70)
    print("# STEP 6: Download proper MSH to Windows, restart Mesh Agent")
    print("#" * 70)

    ps_deploy = f'''$ProgressPreference = "SilentlyContinue"

# Stop agent
Write-Output "Stopping Mesh Agent..."
Stop-Service "Mesh Agent" -Force -ErrorAction SilentlyContinue
Start-Sleep 3
Write-Output "Service stopped."

# Download proper MSH from CT112 HTTP
Write-Output "Downloading MSH from http://{CT112_IP}:8888/meshagent_proper.msh ..."
$wc = New-Object System.Net.WebClient
$wc.DownloadFile("http://{CT112_IP}:8888/meshagent_proper.msh", "C:\\Program Files\\Mesh Agent\\MeshAgent.msh")
Write-Output "Download complete."

Write-Output ""
Write-Output "=== New MSH contents ==="
Get-Content "C:\\Program Files\\Mesh Agent\\MeshAgent.msh"
Write-Output "=== End MSH ==="

# Start agent
Write-Output ""
Write-Output "Starting Mesh Agent..."
Start-Service "Mesh Agent"
Start-Sleep 10

Write-Output ""
Write-Output "=== Service status ==="
Get-Service "*mesh*" | Format-Table Name, Status -AutoSize

Write-Output ""
Write-Output "=== Connections to CT112 ==="
Get-NetTCPConnection | Where-Object {{ $_.RemoteAddress -eq "{CT112_IP}" }} | Format-Table LocalPort, RemotePort, State -AutoSize
'''
    winrm_exec(ps_deploy, "Deploy MSH and restart Mesh Agent")

    # ── Step 7: Wait and verify device in MeshCentral ─────────────────
    print("\n" + "#" * 70)
    print("# STEP 7: Wait 15s, then check MeshCentral for devices")
    print("#" * 70)
    print("Waiting 15 seconds for agent to connect...")
    time.sleep(15)

    cmd_devices = f'pct exec 112 -- {MESHCTRL} {MESH_AUTH} listdevices --json 2>&1'
    out_devices, _ = ssh_exec(ssh, cmd_devices, "listdevices --json")

    # Parse devices
    json_match = re.search(r'(\[.*\])', out_devices or "", re.DOTALL)
    if json_match:
        try:
            devices = json.loads(json_match.group(1))
            print(f"\n{'='*70}")
            print(f"DEVICES FOUND: {len(devices)}")
            for d in devices:
                name = d.get("name", "unknown")
                conn = d.get("conn", 0)
                ip = d.get("ip", "unknown")
                did = d.get("_id", "")
                print(f"  - {name} | conn={conn} | ip={ip} | id={did}")
            print(f"{'='*70}")
        except json.JSONDecodeError:
            print("Could not parse devices JSON")
    elif out_devices and out_devices.strip():
        try:
            devices = json.loads(out_devices.strip())
            print(f"\nDEVICES FOUND: {len(devices)}")
            for d in devices:
                name = d.get("name", "unknown")
                conn = d.get("conn", 0)
                print(f"  - {name} | conn={conn}")
        except json.JSONDecodeError:
            print("Raw device output shown above")
    else:
        print("No devices found or empty output")

    # Cleanup
    ssh.close()
    print("\n" + "#" * 70)
    print("# DONE")
    print("#" * 70)


if __name__ == "__main__":
    main()
