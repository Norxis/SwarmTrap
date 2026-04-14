#!/usr/bin/env python3
"""Reinstall MeshAgent on Windows with new cert hash, then test."""
import paramiko
import winrm
import json
import re
import time

PV1 = "192.168.0.100"
MESH_IP = "172.16.3.112"
WIN_HOST = "http://172.16.3.160:5985/wsman"

def win_run(script, label="", timeout=60):
    if label:
        print(f"\n[{label}]")
    s = winrm.Session(WIN_HOST, auth=("Administrator", "CHANGE_ME"), transport="ntlm",
                      read_timeout_sec=timeout+30, operation_timeout_sec=timeout)
    r = s.run_ps(script)
    out = r.std_out.decode("utf-8", errors="replace").strip()
    if out:
        for line in out.split("\n")[-20:]:
            print(f"  {line}")
    if r.status_code != 0:
        err = r.std_err.decode("utf-8", errors="replace")
        clean = [l for l in err.split("\n") if not any(x in l for x in ["<Obj","CLIXML","<TN","<MS","<I64","<PR","</","progress"]) and l.strip()]
        if clean: print(f"  ERR: {''.join(clean[:5])[:300]}")
    return out

# Connect to PV1
pv1 = paramiko.SSHClient()
pv1.set_missing_host_key_policy(paramiko.AutoAddPolicy())
pv1.connect(PV1, username="root", password="CHANGE_ME", timeout=10)

def pv1_run(cmd, timeout=30):
    print(f"\n[PV1] $ {cmd[:180]}")
    stdin, stdout, stderr = pv1.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if out:
        for line in out.split("\n")[-15:]:
            print(f"  {line}")
    if err: print(f"  ERR: {err[:200]}")
    return out

meshctrl = "/opt/meshcentral/node_modules/meshcentral/meshctrl.js"
mbase = '--url wss://localhost --loginuser admin --loginpass "CHANGE_ME"'

# Get new server cert hash
print("=" * 50)
print("Get new server cert hash")
print("=" * 50)
out = pv1_run('pct exec 112 -- openssl x509 -in /opt/meshcentral/meshcentral-data/webserver-cert-public.crt -fingerprint -sha384 -noout')
hash_match = re.search(r'=([A-Fa-f0-9:]+)', out)
server_hash = hash_match.group(1).replace(":", "").upper() if hash_match else ""
print(f"  New hash: {server_hash[:40]}...")

# Get mesh ID
out = pv1_run(f'pct exec 112 -- node {meshctrl} {mbase} listdevicegroups --json 2>&1')
data = json.loads(out)
mesh_id = data[0]["_id"].split("//")[-1]
print(f"  Mesh ID: {mesh_id}")

# Serve agent from CT112 HTTP
pv1_run('pct exec 112 -- bash -c "pkill -f http.server 2>/dev/null; true"')
pv1_run('pct exec 112 -- bash -c "setsid python3 -m http.server 8888 --directory /tmp </dev/null >/dev/null 2>&1 & sleep 1 && ss -tlnp | grep 8888"')

# Make sure fresh agent binary is available
pv1_run('pct exec 112 -- curl -sk "https://localhost/meshagents?id=4" -o /tmp/meshagent_win64.exe -w "size=%{size_download}"')

# Write new MSH
msh = f"MeshName=WinHunt MeshCentral\nMeshType=2\nMeshID=0x{mesh_id}\nServerID={server_hash}\nMeshServer=wss://{MESH_IP}:443/agent.ashx\n"
stdin, stdout, stderr = pv1.exec_command('pct exec 112 -- tee /tmp/meshagent.msh > /dev/null', timeout=5)
stdin.write(msh)
stdin.channel.shutdown_write()
stdout.read()
print(f"\n  MSH written with new hash")

# Uninstall old agent on Windows
print("\n" + "=" * 50)
print("Reinstall MeshAgent on Windows")
print("=" * 50)

win_run(r"""
# Uninstall existing
$agentExe = "C:\Program Files\Mesh Agent\MeshAgent.exe"
if (Test-Path $agentExe) {
    Start-Process -FilePath $agentExe -ArgumentList "-uninstall" -Wait -NoNewWindow
    Start-Sleep 3
    Write-Output "Old agent uninstalled"
}
# Clean up
Remove-Item "C:\Program Files\Mesh Agent" -Recurse -Force -ErrorAction SilentlyContinue
Write-Output "Cleaned up"
""", "Uninstall old agent")

# Download new agent + MSH
win_run(f"""
$ProgressPreference = "SilentlyContinue"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile("http://{MESH_IP}:8888/meshagent_win64.exe", "$env:TEMP\\meshagent.exe")
$wc.DownloadFile("http://{MESH_IP}:8888/meshagent.msh", "$env:TEMP\\meshagent.msh")
Write-Output "Agent: $((Get-Item "$env:TEMP\\meshagent.exe").Length) bytes"
Write-Output "MSH:"
Get-Content "$env:TEMP\\meshagent.msh"
""", "Download new agent + MSH")

# Install
win_run(r"""
$installDir = "C:\Program Files\Mesh Agent"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item "$env:TEMP\meshagent.exe" "$installDir\MeshAgent.exe" -Force
Copy-Item "$env:TEMP\meshagent.msh" "$installDir\MeshAgent.msh" -Force
Start-Process -FilePath "$installDir\MeshAgent.exe" -ArgumentList "-install" -Wait -NoNewWindow
Start-Sleep 10
$svc = Get-Service | Where-Object { $_.Name -like "*mesh*" }
if ($svc) { Write-Output "Service: $($svc.Name) = $($svc.Status)" }
else { Write-Output "NO SERVICE" }
""", "Install new agent")

# Wait for connection
print("\n  Waiting 20s for agent to connect...")
time.sleep(20)

# Check from MeshCentral
print("\n" + "=" * 50)
print("Check MeshCentral for device")
print("=" * 50)
out = pv1_run(f'pct exec 112 -- node {meshctrl} {mbase} listdevices --json 2>&1')

try:
    devices = json.loads(out)
    if devices:
        node_id = devices[0]["_id"]
        node_name = devices[0].get("name", "unknown")
        print(f"\n  Device found: {node_name} ({node_id})")

        # Test command execution
        print("\n" + "=" * 50)
        print("Test: Execute command via MeshCentral")
        print("=" * 50)
        pv1_run(f'pct exec 112 -- node {meshctrl} {mbase} runcommand --id "{node_id}" --run "hostname && ipconfig /all | findstr IPv4" 2>&1')
        time.sleep(5)
    else:
        print("\n  No devices found yet")
        # Check Windows agent log
        win_run(r"""
Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq "172.16.3.112" } |
    Format-Table LocalPort, RemotePort, State -AutoSize
Get-Service "*mesh*" | Format-Table Name, Status -AutoSize
""", "Check agent connection")
except:
    print(f"  Raw output: {out[:300]}")

# Cleanup
pv1_run('pct exec 112 -- bash -c "pkill -f http.server 2>/dev/null; true"')
pv1.close()
