#!/usr/bin/env python3
"""Fix remaining deploy issues: config, pip packages, Npcap."""
import winrm
import json
import time

WIN_HOST = "http://172.16.3.160:5985/wsman"
ws = winrm.Session(WIN_HOST, auth=("Administrator", "CHANGE_ME"),
                   transport="ntlm", read_timeout_sec=180, operation_timeout_sec=120)

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

# ============================================================
# FIX 1: Write correct config.json (no BOM)
# ============================================================
config = {
    "agent_id": "WINHUNT-SRV25",
    "pcap": {
        "interface": "Ethernet",
        "bpf_filter": "tcp or udp",
        "snap_len": 128,
        "flow_timeout": 90,
        "sweep_interval": 10
    },
    "evidence": {
        "channels": [
            "Security",
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
            "System",
            "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft-Windows-TaskScheduler/Operational",
            "Microsoft-Windows-WMI-Activity/Operational"
        ],
        "poll_interval": 5
    },
    "exporter": {
        "staging_dir": "C:\\Program Files\\DFI\\staging",
        "interval": 30,
        "max_file_age": 3600
    },
    "buffer": {
        "db_path": "C:\\Program Files\\DFI\\agent_buffer.db",
        "max_size_mb": 500
    }
}
config_json = json.dumps(config, indent=2)

# Escape for PowerShell heredoc
config_escaped = config_json.replace("'", "''")

run_ps(f"""
# Stop service first
nssm stop WinHuntAgent 2>$null
Start-Sleep 3

# Write config without BOM
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText('C:\\DFI\\config.json', @'
{config_json}
'@, $utf8NoBom)

# Verify
$bytes = [System.IO.File]::ReadAllBytes('C:\\DFI\\config.json')
$first3 = ($bytes[0..2] | ForEach-Object {{ "0x{{0:X2}}" -f $_ }}) -join " "
Write-Output "First 3 bytes: $first3"
Write-Output "Config content:"
Get-Content 'C:\\DFI\\config.json' | Select-Object -First 8
""", "FIX 1: Write correct config.json")

# ============================================================
# FIX 2: Install pip packages
# ============================================================
run_ps(r"""
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
Write-Output "Python: $(python --version 2>&1)"
Write-Output "pip: $(python -m pip --version 2>&1)"

# Upgrade pip
python -m pip install --upgrade pip 2>&1 | Select-Object -Last 2
Write-Output ""

# Install pywin32
Write-Output "Installing pywin32..."
python -m pip install pywin32 2>&1 | Select-Object -Last 3

# Run pywin32 post-install
Write-Output "`nRunning pywin32 post-install..."
python -m pywin32_postinstall -install 2>&1 | Select-Object -Last 5

# Install pcapy-ng (will fail if no Npcap, but install anyway)
Write-Output "`nInstalling pcapy-ng..."
python -m pip install pcapy-ng 2>&1 | Select-Object -Last 5

# Test imports
Write-Output "`n=== Import tests ==="
python -c "import win32evtlog; print('win32evtlog OK')" 2>&1
python -c "import win32service; print('win32service OK')" 2>&1
python -c "import win32api; print('win32api OK')" 2>&1
python -c "import pcapy; print('pcapy OK')" 2>&1
""", "FIX 2: Install pip packages", timeout=180)

# ============================================================
# FIX 3: Download real Npcap installer
# ============================================================
run_ps(r"""
$ProgressPreference = "SilentlyContinue"

# Check current Npcap state
Write-Output "=== Current Npcap state ==="
if (Test-Path "C:\Program Files\Npcap") {
    Write-Output "Npcap dir exists:"
    Get-ChildItem "C:\Program Files\Npcap" -Name
} else {
    Write-Output "Npcap NOT installed"
}

# Try downloading from npcap.com (free version)
Write-Output "`n=== Download Npcap ==="
$url = "https://npcap.com/dist/npcap-1.80.exe"
try {
    Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\npcap-setup.exe" -UseBasicParsing
    $size = (Get-Item "$env:TEMP\npcap-setup.exe").Length
    Write-Output "Downloaded: $size bytes"
    if ($size -gt 500000) {
        Write-Output "Size OK, installing..."
        Start-Process -FilePath "$env:TEMP\npcap-setup.exe" -ArgumentList "/S /winpcap_mode=yes /loopback_support=yes" -Wait -NoNewWindow
        Start-Sleep 10
        if (Test-Path "C:\Program Files\Npcap\npcap.sys") {
            Write-Output "Npcap: INSTALLED"
            Get-ChildItem "C:\Program Files\Npcap" -Name
        } else {
            Write-Output "Npcap: install may need reboot"
        }
    } else {
        Write-Output "Download too small — got error page"
    }
} catch {
    Write-Output "Download failed: $($_.Exception.Message)"
}
""", "FIX 3: Install Npcap", timeout=120)

# ============================================================
# Restart service and verify
# ============================================================
run_ps(r"""
# Delete old DB to avoid locked error
Remove-Item "C:\Program Files\DFI\agent_buffer.db*" -Force -ErrorAction SilentlyContinue

# Start service
nssm start WinHuntAgent
Start-Sleep 10

$svc = Get-Service WinHuntAgent -ErrorAction SilentlyContinue
Write-Output "Service: $($svc.Status)"

Write-Output "`n=== stderr log (last 15) ==="
if (Test-Path "C:\DFI\stderr.log") {
    Get-Content "C:\DFI\stderr.log" -Tail 15
}
""", "Restart WinHuntAgent + verify")
