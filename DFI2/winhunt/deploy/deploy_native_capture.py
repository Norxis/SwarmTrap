#!/usr/bin/env python3
"""Deploy native capture.py, install Nmap, remove Npcap/pcapy."""
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

def pv1_run(cmd, timeout=60):
    print(f"\n[PV1] $ {cmd[:200]}")
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if out:
        for line in out.split("\n")[-10:]:
            print(f"  {line}")
    if err:
        print(f"  ERR: {err[:300]}")
    return out

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
# STEP 1: Package updated agent + upload to CT112
# ============================================================
print("=" * 60)
print("STEP 1: Deploy updated dfi_agent (native raw socket capture)")
print("=" * 60)

agent_dir = os.path.join(WINHUNT_DIR, "dfi_agent")
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tar:
    tar.add(agent_dir, arcname="dfi_agent")
tarball = buf.getvalue()
print(f"  Tarball: {len(tarball)} bytes")

local_tar = "/tmp/dfi_agent.tar.gz"
with open(local_tar, "wb") as f:
    f.write(tarball)
sftp = c.open_sftp()
sftp.put(local_tar, "/tmp/dfi_agent.tar.gz")
sftp.close()
print("  Uploaded to PV1")

pv1_run("pct push 112 /tmp/dfi_agent.tar.gz /tmp/dfi_agent.tar.gz")

# Update config: remove bpf_filter (not supported with raw sockets), set interface to IP
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
print("  Config written to CT112")

# Start HTTP server
pv1_run('pct exec 112 -- bash -c "pkill -f http.server 2>/dev/null; true"')
pv1_run('pct exec 112 -- bash -c "setsid python3 -m http.server 8888 --directory /tmp </dev/null >/dev/null 2>&1 & sleep 1 && ss -tlnp | grep 8888"')

# ============================================================
# STEP 2: Stop agent, deploy new code + config
# ============================================================
run_ps(f"""
$ProgressPreference = "SilentlyContinue"
nssm stop WinHuntAgent 2>$null
Start-Sleep 3

# Clean old state
Remove-Item "C:\\Program Files\\DFI\\data\\agent_buffer.db*" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\\DFI\\stderr.log" -Force -ErrorAction SilentlyContinue

# Download new agent tarball
$wc = New-Object System.Net.WebClient
$wc.DownloadFile("http://{MESH_IP}:8888/dfi_agent.tar.gz", "$env:TEMP\\dfi_agent.tar.gz")
Write-Output "Tarball: $((Get-Item "$env:TEMP\\dfi_agent.tar.gz").Length) bytes"

# Extract
python -c "import tarfile,shutil; shutil.rmtree(r'C:\\Program Files\\DFI\\agent\\dfi_agent', True); t=tarfile.open(r'$env:TEMP\\dfi_agent.tar.gz'); t.extractall(r'C:\\Program Files\\DFI\\agent'); t.close(); print('extracted')"

# Download new config
$wc.DownloadFile("http://{MESH_IP}:8888/dfi_config.json", "C:\\DFI\\config.json")
Write-Output "Config: interface=$(python -c \\"import json; print(json.load(open(r'C:\\DFI\\config.json'))['pcap']['interface'])\\")"

# Verify capture.py has raw socket code
python -c "from pathlib import Path; t=Path(r'C:\\Program Files\\DFI\\agent\\dfi_agent\\capture.py').read_text(); print('SIO_RCVALL' in t and 'NATIVE' or 'OLD pcapy')"
""", "Deploy updated agent + config")

# ============================================================
# STEP 3: Remove pcapy-ng and Npcap
# ============================================================
run_ps(r"""
Write-Output "=== Remove pcapy-ng ==="
python -m pip uninstall pcapy-ng -y 2>&1 | Select-Object -Last 2

Write-Output "`n=== Uninstall Npcap ==="
if (Test-Path "C:\Program Files\Npcap\Uninstall.exe") {
    Start-Process -FilePath "C:\Program Files\Npcap\Uninstall.exe" -ArgumentList "/S" -Wait -NoNewWindow
    Start-Sleep 3
    if (Test-Path "C:\Program Files\Npcap") { Write-Output "Npcap dir still exists" }
    else { Write-Output "Npcap removed" }
} else {
    Write-Output "No Npcap uninstaller found"
}
""", "Remove Npcap + pcapy-ng")

# ============================================================
# STEP 4: Download and install Nmap
# ============================================================
print("\nDownloading Nmap on CT112...")
pv1_run('pct exec 112 -- curl -sL "https://nmap.org/dist/nmap-7.95-setup.exe" -o /tmp/nmap-setup.exe -w "size=%{size_download}"', timeout=120)
pv1_run('pct exec 112 -- ls -la /tmp/nmap-setup.exe')

run_ps(f"""
$ProgressPreference = "SilentlyContinue"
Write-Output "Downloading Nmap..."
$wc = New-Object System.Net.WebClient
$wc.DownloadFile("http://{MESH_IP}:8888/nmap-setup.exe", "C:\\TEMP\\nmap-setup.exe")
$size = (Get-Item "C:\\TEMP\\nmap-setup.exe").Length
Write-Output "Nmap installer: $size bytes"

if ($size -gt 1000000) {{
    Write-Output "Installing Nmap..."
    Start-Process -FilePath "C:\\TEMP\\nmap-setup.exe" -ArgumentList "/S" -Wait -NoNewWindow
    Start-Sleep 5
    if (Test-Path "C:\\Program Files (x86)\\Nmap\\nmap.exe") {{
        Write-Output "Nmap installed!"
        & "C:\\Program Files (x86)\\Nmap\\nmap.exe" --version 2>&1 | Select-Object -First 2
    }} else {{
        Write-Output "Nmap not found after install"
    }}
}} else {{
    Write-Output "Download too small"
}}
""", "Install Nmap", timeout=300)

# ============================================================
# STEP 5: Start agent and verify capture
# ============================================================
run_ps(r"""
nssm start WinHuntAgent
Start-Sleep 12

$svc = Get-Service WinHuntAgent -ErrorAction SilentlyContinue
Write-Output "Service: $($svc.Status)"

Write-Output "`n=== agent.log (last 10) ==="
Get-Content "C:\Program Files\DFI\logs\agent.log" -Tail 10 -ErrorAction SilentlyContinue

Write-Output "`n=== stderr (last 10) ==="
Get-Content "C:\DFI\stderr.log" -Tail 10 -ErrorAction SilentlyContinue
""", "Start agent + verify")

pv1_run('pct exec 112 -- bash -c "pkill -f http.server 2>/dev/null; true"')
c.close()
print("\n" + "=" * 60)
print("DONE")
print("=" * 60)
