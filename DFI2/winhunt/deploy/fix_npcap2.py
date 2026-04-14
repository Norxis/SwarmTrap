#!/usr/bin/env python3
"""Install Npcap via scheduled task (interactive session)."""
import winrm
import time

WIN_HOST = "http://172.16.3.160:5985/wsman"

def run_ps(script, label="", timeout=120):
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

# Copy installer to a known path
run_ps(r"""
# Use existing installer
$src = "$env:TEMP\npcap-setup.exe"
$dst = "C:\npcap-setup.exe"
Copy-Item $src $dst -Force
$size = (Get-Item $dst).Length
Write-Output "Installer at $dst : $size bytes"
""", "Prepare installer")

# Method 1: Try with scheduled task (runs in SYSTEM interactive context)
run_ps(r"""
# Remove old task
Unregister-ScheduledTask -TaskName "NpcapInstall" -Confirm:$false -ErrorAction SilentlyContinue

# Create action
$action = New-ScheduledTaskAction -Execute "C:\npcap-setup.exe" -Argument "/S /winpcap_mode=yes /loopback_support=yes"
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$task = New-ScheduledTask -Action $action -Principal $principal

Register-ScheduledTask -TaskName "NpcapInstall" -InputObject $task | Out-Null
Start-ScheduledTask -TaskName "NpcapInstall"
Write-Output "Scheduled task started"
""", "Install via scheduled task")

print("\nWaiting 30s for install...")
time.sleep(30)

# Check result
run_ps(r"""
# Check task status
$task = Get-ScheduledTaskInfo -TaskName "NpcapInstall" -ErrorAction SilentlyContinue
Write-Output "Task last result: $($task.LastTaskResult)"

# Check Npcap
Write-Output "`n=== Npcap check ==="
if (Test-Path "C:\Program Files\Npcap") {
    Write-Output "Directory exists:"
    Get-ChildItem "C:\Program Files\Npcap" -Name
} else {
    Write-Output "Directory NOT found"
}

sc.exe query npcap 2>&1

# Check registry
Write-Output "`n=== Registry ==="
Get-ItemProperty "HKLM:\SOFTWARE\Npcap" -ErrorAction SilentlyContinue | Select-Object -Property *

# Cleanup
Unregister-ScheduledTask -TaskName "NpcapInstall" -Confirm:$false -ErrorAction SilentlyContinue
""", "Check Npcap after scheduled task")

# If still not installed, try WinPcap as fallback
run_ps(r"""
if (-not (Test-Path "C:\Program Files\Npcap\npcap.sys")) {
    Write-Output "Npcap still not installed."
    Write-Output "Trying alternative: check if pcapy-ng works with raw sockets..."
    python -c "import pcapy; print('pcapy works!', pcapy.findalldevs())" 2>&1

    Write-Output "`nNpcap may require interactive install (GUI EULA)."
    Write-Output "Options:"
    Write-Output "  1. RDP to 172.16.3.160 and run C:\npcap-setup.exe manually"
    Write-Output "  2. Use Npcap OEM edition (supports true silent install)"
    Write-Output "  3. Skip packet capture, use evidence-only mode"
} else {
    Write-Output "Npcap installed!"
    # Test pcapy
    python -c "import pcapy; devs = pcapy.findalldevs(); print(f'pcapy OK: {len(devs)} devices'); [print(f'  {d}') for d in devs]" 2>&1
}
""", "Final Npcap status")
