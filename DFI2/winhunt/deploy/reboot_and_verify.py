#!/usr/bin/env python3
"""Reboot Windows 160, wait for it to come back, verify Npcap + agent."""
import winrm
import time

WIN_HOST = "http://172.16.3.160:5985/wsman"

def run_ps(script, label="", timeout=60):
    if label:
        print(f"\n{'=' * 50}")
        print(label)
        print('=' * 50)
    s = winrm.Session(WIN_HOST, auth=("Administrator", "CHANGE_ME"),
                      transport="ntlm", read_timeout_sec=timeout+60, operation_timeout_sec=timeout)
    r = s.run_ps(script)
    out = r.std_out.decode("utf-8", errors="replace").strip()
    if out:
        for line in out.split("\n"):
            print(f"  {line}")
    if r.status_code != 0:
        err = r.std_err.decode("utf-8", errors="replace")
        clean = [l for l in err.split("\n")
                 if not any(x in l for x in ["<Obj","CLIXML","<TN","<MS","<I64","<PR","</","progress"]) and l.strip()]
        if clean:
            print(f"  ERR: {''.join(clean[:5])[:500]}")
    return out

# Reboot
print("Rebooting 172.16.3.160...")
try:
    s = winrm.Session(WIN_HOST, auth=("Administrator", "CHANGE_ME"),
                      transport="ntlm", read_timeout_sec=30, operation_timeout_sec=15)
    s.run_ps("Restart-Computer -Force")
except Exception as e:
    print(f"  Reboot command sent (connection dropped as expected): {type(e).__name__}")

# Wait for reboot
print("\nWaiting 60s for reboot...")
time.sleep(60)

# Poll until WinRM is back
for attempt in range(12):
    try:
        s = winrm.Session(WIN_HOST, auth=("Administrator", "CHANGE_ME"),
                          transport="ntlm", read_timeout_sec=15, operation_timeout_sec=10)
        r = s.run_ps("hostname")
        hostname = r.std_out.decode().strip()
        print(f"\n  WinRM back online: {hostname} (attempt {attempt+1})")
        break
    except Exception:
        print(f"  Attempt {attempt+1}/12: not ready yet...")
        time.sleep(15)
else:
    print("FATAL: WinRM did not come back after 3 minutes")
    exit(1)

# Wait for services to stabilize
print("Waiting 20s for services to start...")
time.sleep(20)

# Verify everything
run_ps(r"""
Write-Output "=== Npcap ==="
if (Test-Path "C:\Program Files\Npcap\npcap.sys") { Write-Output "npcap.sys: FOUND" }
else { Write-Output "npcap.sys: NOT FOUND" }

Get-ChildItem "C:\Program Files\Npcap" -Name -ErrorAction SilentlyContinue
sc.exe query npcap 2>&1

Write-Output "`n=== pcapy import ==="
python -c "import pcapy; devs = pcapy.findalldevs(); print(f'pcapy OK: {len(devs)} devices'); [print(f'  {d}') for d in devs]" 2>&1

Write-Output "`n=== pywin32 import ==="
python -c "import win32evtlog; print('win32evtlog OK')" 2>&1

Write-Output "`n=== Services ==="
Get-Service "Mesh Agent","WinHuntAgent" -ErrorAction SilentlyContinue | Format-Table Name, Status -AutoSize

Write-Output "`n=== MeshCentral connection ==="
Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq "172.16.3.112" } |
    Format-Table LocalPort, RemotePort, State -AutoSize

Write-Output "`n=== stderr log ==="
if (Test-Path "C:\DFI\stderr.log") {
    Get-Content "C:\DFI\stderr.log" -Tail 15
} else { Write-Output "No stderr log" }

Write-Output "`n=== agent.log ==="
if (Test-Path "C:\Program Files\DFI\logs\agent.log") {
    Get-Content "C:\Program Files\DFI\logs\agent.log" -Tail 15
} else { Write-Output "No agent.log" }

Write-Output "`n=== staging dir ==="
if (Test-Path "C:\Program Files\DFI\staging") {
    $files = Get-ChildItem "C:\Program Files\DFI\staging" -File
    Write-Output "Files: $($files.Count)"
    $files | Select-Object -Last 5 | ForEach-Object { Write-Output "  $($_.Name) ($($_.Length) bytes)" }
} else { Write-Output "No staging dir" }
""", "Post-reboot verification", timeout=90)
