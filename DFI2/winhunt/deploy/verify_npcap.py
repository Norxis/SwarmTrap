#!/usr/bin/env python3
"""Verify Npcap + pcapy, restart agent for full capture."""
import winrm

WIN_HOST = "http://172.16.3.160:5985/wsman"
s = winrm.Session(WIN_HOST, auth=("Administrator", "CHANGE_ME"),
                  transport="ntlm", read_timeout_sec=90, operation_timeout_sec=60)

r = s.run_ps(r"""
Write-Output "=== Npcap ==="
if (Test-Path "C:\Program Files\Npcap\npcap.sys") { Write-Output "npcap.sys: FOUND" }
Get-ChildItem "C:\Program Files\Npcap" -Name -ErrorAction SilentlyContinue
sc.exe query npcap 2>&1

Write-Output "`n=== pcapy import ==="
python -c "import pcapy; devs = pcapy.findalldevs(); print(f'pcapy OK: {len(devs)} devices'); [print(f'  {d}') for d in devs]" 2>&1

Write-Output "`n=== Restart agent ==="
nssm restart WinHuntAgent
Start-Sleep 12

Get-Service WinHuntAgent | Format-Table Name, Status -AutoSize

Write-Output "`n=== stderr log ==="
Get-Content "C:\DFI\stderr.log" -Tail 15 -ErrorAction SilentlyContinue

Write-Output "`n=== agent.log ==="
Get-Content "C:\Program Files\DFI\logs\agent.log" -Tail 15 -ErrorAction SilentlyContinue

Write-Output "`n=== staging dir ==="
$files = Get-ChildItem "C:\Program Files\DFI\staging" -File -ErrorAction SilentlyContinue
Write-Output "Files: $($files.Count)"
$files | Select-Object -Last 5 | ForEach-Object { Write-Output "  $($_.Name) ($($_.Length) bytes)" }
""")

print(r.std_out.decode("utf-8", errors="replace"))
if r.status_code != 0:
    err = r.std_err.decode("utf-8", errors="replace")
    clean = [l for l in err.split("\n")
             if not any(x in l for x in ["<Obj","CLIXML","<TN","<MS","<I64","<PR","</","progress"]) and l.strip()]
    if clean:
        print("ERR:", "\n".join(clean[:5]))
