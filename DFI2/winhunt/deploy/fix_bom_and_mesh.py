#!/usr/bin/env python3
"""Fix config.json BOM + verify MeshCentral connectivity."""
import paramiko
import winrm
import time

PV1 = "192.168.0.100"
WIN_HOST = "http://172.16.3.160:5985/wsman"

# Fix 1: Rewrite config.json without BOM
print("=" * 50)
print("FIX: Rewrite config.json without BOM")
print("=" * 50)

s = winrm.Session(WIN_HOST, auth=("Administrator", "CHANGE_ME"), transport="ntlm",
                  read_timeout_sec=60, operation_timeout_sec=45)
r = s.run_ps(r"""
# Read config, strip BOM, rewrite with .NET (no BOM)
$path = "C:\DFI\config.json"
$content = Get-Content $path -Raw
# Use .NET to write without BOM
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($path, $content, $utf8NoBom)
Write-Output "Rewrote config.json without BOM"

# Verify first bytes
$bytes = [System.IO.File]::ReadAllBytes($path)
$first3 = ($bytes[0..2] | ForEach-Object { "0x{0:X2}" -f $_ }) -join " "
Write-Output "First 3 bytes: $first3 (should NOT be 0xEF 0xBB 0xBF)"

# Restart WinHuntAgent
nssm restart WinHuntAgent
Start-Sleep 8
$svc = Get-Service WinHuntAgent
Write-Output "Service: $($svc.Name) = $($svc.Status)"

# Check logs
if (Test-Path "C:\DFI\stderr.log") {
    Write-Output "`n=== stderr (last 10) ==="
    Get-Content "C:\DFI\stderr.log" -Tail 10
}
if (Test-Path "C:\Program Files\DFI\logs\agent.log") {
    Write-Output "`n=== agent.log (last 10) ==="
    Get-Content "C:\Program Files\DFI\logs\agent.log" -Tail 10
}
""")
out = r.std_out.decode("utf-8", errors="replace")
print(out)

# Fix 2: Check MeshCentral connectivity from CT112 to Windows
print("\n" + "=" * 50)
print("CHECK: MeshCentral → Windows connectivity")
print("=" * 50)

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(PV1, username="root", password="CHANGE_ME", timeout=10)

def run(cmd):
    print(f"$ {cmd[:150]}")
    stdin, stdout, stderr = c.exec_command(cmd, timeout=15)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if out: print(f"  {out}")
    if err: print(f"  ERR: {err}")
    return out

# Ping
run("pct exec 112 -- ping -c 2 -W 3 172.16.3.160")

# Check if MeshCentral sees the agent
meshctrl = "/opt/meshcentral/node_modules/meshcentral/meshctrl.js"
mbase = '--url wss://localhost --loginuser admin --loginpass "CHANGE_ME"'
run(f'pct exec 112 -- node {meshctrl} {mbase} listdevices --group "WinHunt-Test" 2>&1')

# Check MeshCentral logs for connection attempts
run("pct exec 112 -- journalctl -u meshcentral --no-pager -n 20 | grep -i -E 'agent|connect|172.16.3'")

# Check Windows firewall for agent port on Windows side (via WinRM)
r2 = s.run_ps(r"""
# Check if Mesh Agent service is running
Get-Service | Where-Object { $_.Name -like "*mesh*" } | Format-Table Name, Status -AutoSize

# Check Mesh Agent log
if (Test-Path "C:\Program Files\Mesh Agent") {
    Get-ChildItem "C:\Program Files\Mesh Agent" -Name
}

# Check outbound connection from agent
Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq "172.16.3.112" } |
    Format-Table LocalPort, RemotePort, State -AutoSize
""")
print("\n[Windows MeshAgent status]")
print(r2.std_out.decode("utf-8", errors="replace"))

c.close()
