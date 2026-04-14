#!/usr/bin/env python3
"""Debug and fix Npcap installation on Windows 160."""
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

# Debug: check what happened with the installer
run_ps(r"""
# Check installer file
$installer = "$env:TEMP\npcap-setup.exe"
if (Test-Path $installer) {
    $size = (Get-Item $installer).Length
    Write-Output "Installer: $size bytes"
    # Check if it's actually an EXE (PE header)
    $bytes = [System.IO.File]::ReadAllBytes($installer)
    $magic = [System.Text.Encoding]::ASCII.GetString($bytes[0..1])
    Write-Output "Magic: $magic (should be MZ for EXE)"
} else {
    Write-Output "Installer not found at $installer"
}

# Check for any Npcap traces
Write-Output "`n=== Registry ==="
Get-ItemProperty "HKLM:\SOFTWARE\Npcap" -ErrorAction SilentlyContinue | Format-List
Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Npcap" -ErrorAction SilentlyContinue | Format-List

# Check for WinPcap
Get-ItemProperty "HKLM:\SOFTWARE\WinPcap" -ErrorAction SilentlyContinue | Format-List

# Check installed programs
Write-Output "`n=== Installed programs with pcap/npcap ==="
Get-WmiObject Win32_Product | Where-Object { $_.Name -like "*pcap*" -or $_.Name -like "*npcap*" } | Format-List Name, Version

# Check drivers
Write-Output "`n=== Npcap-related drivers ==="
driverquery /v 2>&1 | Select-String -Pattern "npcap|npf|winpcap" -CaseSensitive:$false

# Check services
Write-Output "`n=== Npcap-related services ==="
Get-Service | Where-Object { $_.Name -like "*npcap*" -or $_.Name -like "*npf*" } | Format-Table Name, Status, DisplayName -AutoSize
""", "Debug Npcap install state")

# Try fresh download and install with verbose logging
run_ps(r"""
$ProgressPreference = "SilentlyContinue"

# Download fresh copy
Write-Output "Downloading Npcap 1.80..."
$url = "https://npcap.com/dist/npcap-1.80.exe"
Invoke-WebRequest -Uri $url -OutFile "C:\TEMP\npcap.exe" -UseBasicParsing
$size = (Get-Item "C:\TEMP\npcap.exe").Length
Write-Output "Downloaded: $size bytes"

if ($size -lt 500000) {
    Write-Output "FAILED: file too small"
    # Show content (probably HTML error page)
    Get-Content "C:\TEMP\npcap.exe" -TotalCount 5
    exit 1
}

# Run installer with logging
Write-Output "`nInstalling Npcap..."
$proc = Start-Process -FilePath "C:\TEMP\npcap.exe" -ArgumentList "/S /winpcap_mode=yes /loopback_support=yes /D=C:\Program Files\Npcap" -Wait -NoNewWindow -PassThru
Write-Output "Installer exit code: $($proc.ExitCode)"

Start-Sleep 5

# Check result
Write-Output "`n=== Post-install check ==="
if (Test-Path "C:\Program Files\Npcap") {
    Write-Output "Npcap directory exists:"
    Get-ChildItem "C:\Program Files\Npcap" -Name
} else {
    Write-Output "Npcap directory NOT created"
}

sc.exe query npcap 2>&1
sc.exe query npf 2>&1
""", "Fresh Npcap install attempt", timeout=180)
