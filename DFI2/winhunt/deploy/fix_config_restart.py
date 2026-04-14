#!/usr/bin/env python3
"""Fix config.json field names and restart agent."""
import winrm
import json
import paramiko

WIN_HOST = "http://172.16.3.160:5985/wsman"
PV1 = "192.168.0.100"
MESH_IP = "172.16.3.112"

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

# Write config to CT112 and serve via HTTP
config = {
    "vm_id": "WINHUNT-SRV25",
    "mgmt_nic_ip": "172.16.3.160",
    "agent_port": 9200,
    "token": "",
    "buffer_path": "C:\\Program Files\\DFI\\data\\agent_buffer.db",
    "log_dir": "C:\\Program Files\\DFI\\logs",
    "log_level": "INFO",
    "retention_days": 7,
    "pcap": {
        "interface": "Ethernet",
        "bpf_filter": "tcp or udp",
        "snap_len": 128,
        "flow_timeout_s": 90,
        "max_active_flows": 50000
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
        ]
    },
    "exporter": {
        "staging_dir": "C:\\Program Files\\DFI\\staging",
        "export_interval_s": 30,
        "max_rows_per_file": 10000,
        "retention_hours": 24
    },
    "services": {
        "rdp": {"ports": [3389], "enabled": True},
        "smb": {"ports": [445], "enabled": True},
        "winrm": {"ports": [5985, 5986], "enabled": True},
        "mssql": {"ports": [1433], "enabled": True}
    }
}

# Upload config to CT112 and serve via HTTP
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(PV1, username="root", password="CHANGE_ME", timeout=10)

config_json = json.dumps(config, indent=2)
stdin, stdout, stderr = c.exec_command('pct exec 112 -- tee /tmp/dfi_config.json > /dev/null', timeout=5)
stdin.write(config_json)
stdin.channel.shutdown_write()
stdout.read()
print("Config written to CT112")

# Start HTTP server
c.exec_command('pct exec 112 -- bash -c "pkill -f http.server 2>/dev/null; true"', timeout=5)
stdin, stdout, stderr = c.exec_command('pct exec 112 -- bash -c "setsid python3 -m http.server 8888 --directory /tmp </dev/null >/dev/null 2>&1 & sleep 1 && ss -tlnp | grep 8888"', timeout=10)
print(stdout.read().decode().strip())

# Stop service, download config, restart
run_ps(r"""
nssm stop WinHuntAgent 2>$null
Start-Sleep 3

# Clean old state
Remove-Item "C:\Program Files\DFI\data\agent_buffer.db*" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\DFI\stderr.log" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\DFI\stdout.log" -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "C:\Program Files\DFI\data" | Out-Null
New-Item -ItemType Directory -Force -Path "C:\Program Files\DFI\staging" | Out-Null
New-Item -ItemType Directory -Force -Path "C:\Program Files\DFI\logs" | Out-Null

# Download fresh config from CT112
$ProgressPreference = "SilentlyContinue"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile("http://172.16.3.112:8888/dfi_config.json", "C:\DFI\config.json")

Write-Output "=== Config ==="
Get-Content "C:\DFI\config.json" | Select-Object -First 8

# Check first bytes (no BOM)
$bytes = [System.IO.File]::ReadAllBytes("C:\DFI\config.json")
$first3 = ($bytes[0..2] | ForEach-Object { "0x{0:X2}" -f $_ }) -join " "
Write-Output "First bytes: $first3"
""", "Stop + write config")

# Check Npcap
run_ps(r"""
Write-Output "=== Npcap ==="
if (Test-Path "C:\Program Files\Npcap\npcap.sys") { Write-Output "npcap.sys: FOUND" }
else { Write-Output "npcap.sys: NOT FOUND" }

# Check all Npcap locations
foreach ($dir in @("C:\Program Files\Npcap", "C:\Windows\System32\Npcap", "C:\Windows\SysWOW64\Npcap")) {
    if (Test-Path $dir) {
        Write-Output "`n$dir :"
        Get-ChildItem $dir -Name
    }
}

sc.exe query npcap 2>&1

# Test pcapy import
Write-Output "`n=== pcapy import test ==="
python -c "import pcapy; print('pcapy OK:', pcapy.findalldevs())" 2>&1
""", "Check Npcap + pcapy")

# Start service
run_ps(r"""
nssm start WinHuntAgent
Start-Sleep 12

$svc = Get-Service WinHuntAgent -ErrorAction SilentlyContinue
Write-Output "Service: $($svc.Status)"

Write-Output "`n=== stderr log ==="
if (Test-Path "C:\DFI\stderr.log") {
    Get-Content "C:\DFI\stderr.log" -Tail 20
} else { Write-Output "No log yet" }

Write-Output "`n=== agent.log ==="
if (Test-Path "C:\Program Files\DFI\logs\agent.log") {
    Get-Content "C:\Program Files\DFI\logs\agent.log" -Tail 15
} else { Write-Output "No agent.log yet" }
""", "Start service + check logs")

# Cleanup
c.exec_command('pct exec 112 -- bash -c "pkill -f http.server 2>/dev/null; true"', timeout=5)
c.close()
