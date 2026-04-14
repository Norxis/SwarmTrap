#!/usr/bin/env python3
"""Deploy updated capture.py (native raw sockets, no Npcap) and restart."""
import paramiko
import winrm
import json
import time
import os
import tarfile
import io

PV1 = "192.168.0.100"
MESH_IP = "172.16.3.112"
WIN_HOST = "http://172.16.3.160:5985/wsman"
WINHUNT_DIR = "/home/colo8gent/DFI2/winhunt"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(PV1, username="root", password="CHANGE_ME", timeout=10)

def pv1_run(cmd, timeout=30):
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    if out:
        for line in out.split("\n")[-5:]:
            print(f"  {line}")
    return out

def run_ps(script, label="", timeout=90):
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

# Package agent tarball
agent_dir = os.path.join(WINHUNT_DIR, "dfi_agent")
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tar:
    tar.add(agent_dir, arcname="dfi_agent")
tarball = buf.getvalue()
print(f"Tarball: {len(tarball)} bytes")

local_tar = "/tmp/dfi_agent.tar.gz"
with open(local_tar, "wb") as f:
    f.write(tarball)
sftp = c.open_sftp()
sftp.put(local_tar, "/tmp/dfi_agent.tar.gz")
sftp.close()
pv1_run("pct push 112 /tmp/dfi_agent.tar.gz /tmp/dfi_agent.tar.gz")

# Write updated config (interface = IP for raw socket bind)
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
        "interface": "Ethernet0",
        "snap_len": 65535,
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
config_json = json.dumps(config, indent=2)
stdin, stdout, stderr = c.exec_command('pct exec 112 -- tee /tmp/dfi_config.json > /dev/null', timeout=5)
stdin.write(config_json)
stdin.channel.shutdown_write()
stdout.read()

# Serve via HTTP
c.exec_command('pct exec 112 -- bash -c "pkill -f http.server 2>/dev/null; true"', timeout=5)
stdin2, stdout2, _ = c.exec_command('pct exec 112 -- bash -c "setsid python3 -m http.server 8888 --directory /tmp </dev/null >/dev/null 2>&1 & sleep 1 && ss -tlnp | grep 8888"', timeout=10)
print(stdout2.read().decode().strip())

# Deploy to Windows
run_ps(f"""
$ProgressPreference = "SilentlyContinue"
nssm stop WinHuntAgent 2>$null
Start-Sleep 3
Remove-Item "C:\\Program Files\\DFI\\data\\agent_buffer.db*" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\\DFI\\stderr.log" -Force -ErrorAction SilentlyContinue

$wc = New-Object System.Net.WebClient
$wc.DownloadFile("http://{MESH_IP}:8888/dfi_agent.tar.gz", "$env:TEMP\\dfi_agent.tar.gz")
python -c "import tarfile,shutil; shutil.rmtree(r'C:\\Program Files\\DFI\\agent\\dfi_agent', True); t=tarfile.open(r'%TEMP%\\dfi_agent.tar.gz'.replace('%TEMP%',__import__('os').environ['TEMP'])); t.extractall(r'C:\\Program Files\\DFI\\agent'); t.close(); print('extracted')"

$wc.DownloadFile("http://{MESH_IP}:8888/dfi_config.json", "C:\\DFI\\config.json")

# Verify native capture
python -c "from pathlib import Path; t=Path(r'C:\\Program Files\\DFI\\agent\\dfi_agent\\capture.py').read_text(); print('SIO_RCVALL' in t and 'NATIVE raw socket' or 'OLD pcapy')"

nssm start WinHuntAgent
Start-Sleep 12

Write-Output "`n=== agent.log ==="
Get-Content "C:\\Program Files\\DFI\\logs\\agent.log" -Tail 10

Write-Output "`n=== stderr ==="
Get-Content "C:\\DFI\\stderr.log" -Tail 10 -ErrorAction SilentlyContinue
""", "Deploy + restart")

c.exec_command('pct exec 112 -- bash -c "pkill -f http.server 2>/dev/null; true"', timeout=5)
c.close()
