#!/usr/bin/env python3
"""Deploy dfi_agent to 172.16.3.160 via MeshCentral from CT112."""
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

# ============================================================
# Connect to PV1 + WinRM
# ============================================================
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(PV1, username="root", password="CHANGE_ME", timeout=10)

ws = winrm.Session(WIN_HOST, auth=("Administrator", "CHANGE_ME"),
                   transport="ntlm", read_timeout_sec=120, operation_timeout_sec=90)

meshctrl = "/opt/meshcentral/node_modules/meshcentral/meshctrl.js"
mbase = '--url wss://localhost --loginuser admin --loginpass "CHANGE_ME"'

def pv1_run(cmd, timeout=30):
    print(f"\n[PV1] $ {cmd[:200]}")
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if out:
        for line in out.split("\n")[-15:]:
            print(f"  {line}")
    if err:
        print(f"  ERR: {err[:300]}")
    return out

def mc_cmd(node_id, ps_cmd, label=""):
    """Run PowerShell on Windows via MeshCentral runcommand (fire-and-forget)."""
    if label:
        print(f"\n  [MC] {label}")
    escaped = ps_cmd.replace('"', '\\"')
    pv1_run(f'pct exec 112 -- node {meshctrl} {mbase} runcommand --id "{node_id}" --run "{escaped}" --powershell 2>&1')

def win_check(ps, label=""):
    """Verify state on Windows via WinRM."""
    if label:
        print(f"\n  [WinRM verify: {label}]")
    r = ws.run_ps(ps)
    out = r.std_out.decode("utf-8", errors="replace").strip()
    if out:
        for line in out.split("\n"):
            print(f"    {line}")
    if r.status_code != 0:
        err = r.std_err.decode("utf-8", errors="replace")
        clean = [l for l in err.split("\n")
                 if not any(x in l for x in ["<Obj","CLIXML","<TN","<MS","<I64","<PR","</","progress"]) and l.strip()]
        if clean:
            print(f"    ERR: {''.join(clean[:5])[:300]}")
    return out

# Get node ID
print("=" * 60)
print("DEPLOY dfi_agent via MeshCentral")
print("=" * 60)

out = pv1_run(f'pct exec 112 -- node {meshctrl} {mbase} listdevices --json 2>&1')
devices = json.loads(out)
if not devices:
    print("FATAL: No devices in MeshCentral!")
    c.close()
    exit(1)
node_id = devices[0]["_id"]
print(f"\nTarget: {devices[0]['name']} ({devices[0]['host']}) conn={devices[0].get('conn')}")

# ============================================================
# STEP 0: Check what's already installed
# ============================================================
print("\n" + "=" * 60)
print("STEP 0: Pre-deploy inventory")
print("=" * 60)

win_check(r"""
Write-Output "=== Python ==="
python --version 2>&1

Write-Output "`n=== NSSM ==="
nssm version 2>&1 | Select-Object -First 1

Write-Output "`n=== Npcap ==="
if (Test-Path "C:\Program Files\Npcap\npcap.sys") { Write-Output "INSTALLED" }
else { Write-Output "NOT INSTALLED" }

Write-Output "`n=== DFI Agent files ==="
if (Test-Path "C:\Program Files\DFI\agent\dfi_agent\__main__.py") {
    $count = (Get-ChildItem "C:\Program Files\DFI\agent\dfi_agent" -Filter *.py).Count
    Write-Output "DEPLOYED ($count .py files)"
} else { Write-Output "NOT DEPLOYED" }

Write-Output "`n=== Config ==="
if (Test-Path "C:\DFI\config.json") { Write-Output "EXISTS" } else { Write-Output "MISSING" }

Write-Output "`n=== pip packages ==="
python -m pip list 2>&1 | Select-String "pcapy|pywin32|scapy"

Write-Output "`n=== WinHuntAgent service ==="
$svc = Get-Service WinHuntAgent -ErrorAction SilentlyContinue
if ($svc) { Write-Output "$($svc.Name) = $($svc.Status)" } else { Write-Output "NOT INSTALLED" }

Write-Output "`n=== Npcap driver test ==="
python -c "import pcapy; print('pcapy OK')" 2>&1
python -c "import win32evtlog; print('pywin32 OK')" 2>&1
""", "Pre-deploy inventory")

# ============================================================
# STEP 1: Package dfi_agent and copy to CT112
# ============================================================
print("\n" + "=" * 60)
print("STEP 1: Package dfi_agent → CT112")
print("=" * 60)

# Create tarball in memory
agent_dir = os.path.join(WINHUNT_DIR, "dfi_agent")
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tar:
    tar.add(agent_dir, arcname="dfi_agent")
tarball = buf.getvalue()
print(f"  Tarball: {len(tarball)} bytes")

# Upload to CT112 via paramiko + pct push
local_tar = "/tmp/dfi_agent.tar.gz"
with open(local_tar, "wb") as f:
    f.write(tarball)

# Push to PV1, then to CT112
sftp = c.open_sftp()
sftp.put(local_tar, "/tmp/dfi_agent.tar.gz")
sftp.close()
print("  Uploaded to PV1:/tmp/dfi_agent.tar.gz")

pv1_run("pct push 112 /tmp/dfi_agent.tar.gz /tmp/dfi_agent.tar.gz")
print("  Pushed to CT112:/tmp/dfi_agent.tar.gz")

# Also create config.json on CT112
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
stdin, stdout, stderr = c.exec_command('pct exec 112 -- tee /tmp/dfi_config.json > /dev/null', timeout=5)
stdin.write(config_json)
stdin.channel.shutdown_write()
stdout.read()
print("  Config written to CT112:/tmp/dfi_config.json")

# Start HTTP server on CT112
pv1_run('pct exec 112 -- bash -c "pkill -f http.server 2>/dev/null; true"')
pv1_run('pct exec 112 -- bash -c "setsid python3 -m http.server 8888 --directory /tmp </dev/null >/dev/null 2>&1 & sleep 1 && ss -tlnp | grep 8888"')

# ============================================================
# STEP 2: Deploy via MeshCentral runcommand
# ============================================================
print("\n" + "=" * 60)
print("STEP 2: Deploy agent files via MeshCentral")
print("=" * 60)

# 2a: Download and extract agent tarball
mc_cmd(node_id, f"""
$ProgressPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force -Path 'C:\\Program Files\\DFI\\agent' | Out-Null
$wc = New-Object System.Net.WebClient
$wc.DownloadFile('http://{MESH_IP}:8888/dfi_agent.tar.gz', '$env:TEMP\\dfi_agent.tar.gz')
""", "Download agent tarball")
time.sleep(8)

# 2b: Extract tarball using Python (tar is not native on Windows)
mc_cmd(node_id, """
python -c "import tarfile,os,shutil; t=tarfile.open(os.environ['TEMP']+'\\\\dfi_agent.tar.gz'); shutil.rmtree('C:\\\\Program Files\\\\DFI\\\\agent\\\\dfi_agent', True); t.extractall('C:\\\\Program Files\\\\DFI\\\\agent'); t.close(); print('extracted')"
""", "Extract agent tarball")
time.sleep(5)

# 2c: Download config
mc_cmd(node_id, f"""
$ProgressPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force -Path 'C:\\DFI' | Out-Null
$wc = New-Object System.Net.WebClient
$wc.DownloadFile('http://{MESH_IP}:8888/dfi_config.json', 'C:\\DFI\\config.json')
""", "Download config.json")
time.sleep(5)

# Verify agent files + config
win_check(r"""
Write-Output "=== Agent files ==="
$files = (Get-ChildItem "C:\Program Files\DFI\agent\dfi_agent" -Filter *.py -ErrorAction SilentlyContinue)
Write-Output "Python files: $($files.Count)"
$files | ForEach-Object { Write-Output "  $($_.Name)" }

Write-Output "`n=== Config ==="
if (Test-Path "C:\DFI\config.json") {
    $bytes = [System.IO.File]::ReadAllBytes("C:\DFI\config.json")
    $first3 = ($bytes[0..2] | ForEach-Object { "0x{0:X2}" -f $_ }) -join " "
    Write-Output "First 3 bytes: $first3 (no BOM = good if 0x7B)"
    Get-Content "C:\DFI\config.json" | Select-Object -First 5
} else { Write-Output "MISSING" }
""", "Agent files + config")

# ============================================================
# STEP 3: Install Npcap via MeshCentral
# ============================================================
print("\n" + "=" * 60)
print("STEP 3: Install Npcap")
print("=" * 60)

# Download Npcap to CT112 first
pv1_run('pct exec 112 -- bash -c "test -f /tmp/npcap-1.80-oem.exe && echo EXISTS || curl -sL https://npcap.com/dist/npcap-1.80-oem.exe -o /tmp/npcap-1.80-oem.exe && echo DOWNLOADED"', timeout=60)
pv1_run('pct exec 112 -- ls -la /tmp/npcap-1.80-oem.exe')

# Download Npcap to Windows
mc_cmd(node_id, f"""
$ProgressPreference = 'SilentlyContinue'
$wc = New-Object System.Net.WebClient
$wc.DownloadFile('http://{MESH_IP}:8888/npcap-1.80-oem.exe', '$env:TEMP\\npcap-setup.exe')
""", "Download Npcap installer")
time.sleep(10)

# Install Npcap silently
mc_cmd(node_id, """
Start-Process -FilePath $env:TEMP\\npcap-setup.exe -ArgumentList '/S /winpcap_mode=yes /loopback_support=yes' -Wait -NoNewWindow
Start-Sleep 10
""", "Install Npcap (silent)")
time.sleep(20)

win_check(r"""
Write-Output "=== Npcap check ==="
if (Test-Path "C:\Program Files\Npcap\npcap.sys") { Write-Output "npcap.sys: FOUND" }
else { Write-Output "npcap.sys: NOT FOUND" }
if (Test-Path "C:\Program Files\Npcap\NPFInstall.exe") { Write-Output "NPFInstall.exe: FOUND" }
else { Write-Output "NPFInstall.exe: NOT FOUND" }
Get-ChildItem "C:\Program Files\Npcap" -Name -ErrorAction SilentlyContinue
sc.exe query npcap 2>&1
""", "Npcap installation")

# ============================================================
# STEP 4: Install pip packages via MeshCentral
# ============================================================
print("\n" + "=" * 60)
print("STEP 4: Install pip packages")
print("=" * 60)

mc_cmd(node_id, """
python -m pip install --upgrade pip 2>&1 | Select-Object -Last 1
python -m pip install pcapy-ng pywin32 2>&1 | Select-Object -Last 3
""", "pip install pcapy-ng pywin32")
time.sleep(30)

win_check(r"""
Write-Output "=== pip packages ==="
python -m pip list 2>&1 | Select-String "pcapy|pywin32|pypiwin32"
Write-Output "`n=== Import test ==="
python -c "import pcapy; print('pcapy OK')" 2>&1
python -c "import win32evtlog; print('pywin32 OK')" 2>&1
python -c "import win32service; print('win32service OK')" 2>&1
""", "pip packages + import test")

# ============================================================
# STEP 5: Create staging dir + NSSM service via MeshCentral
# ============================================================
print("\n" + "=" * 60)
print("STEP 5: Create staging dir + NSSM service")
print("=" * 60)

mc_cmd(node_id, """
New-Item -ItemType Directory -Force -Path 'C:\\Program Files\\DFI\\staging' | Out-Null
New-Item -ItemType Directory -Force -Path 'C:\\Program Files\\DFI\\logs' | Out-Null
""", "Create directories")
time.sleep(3)

# Stop old service if exists
mc_cmd(node_id, """
nssm stop WinHuntAgent 2>$null
nssm remove WinHuntAgent confirm 2>$null
Start-Sleep 2
""", "Remove old WinHuntAgent service")
time.sleep(5)

# Create new service
mc_cmd(node_id, """
$py = (Get-Command python).Source
nssm install WinHuntAgent $py
nssm set WinHuntAgent AppParameters '-m dfi_agent --config C:\\DFI\\config.json'
nssm set WinHuntAgent AppDirectory 'C:\\Program Files\\DFI\\agent'
nssm set WinHuntAgent DisplayName 'WinHunt DFI Agent'
nssm set WinHuntAgent Start SERVICE_AUTO_START
nssm set WinHuntAgent AppStdout 'C:\\DFI\\stdout.log'
nssm set WinHuntAgent AppStderr 'C:\\DFI\\stderr.log'
nssm set WinHuntAgent AppRotateFiles 1
nssm set WinHuntAgent AppRotateBytes 10485760
nssm start WinHuntAgent
""", "Install + start WinHuntAgent via NSSM")
time.sleep(15)

win_check(r"""
Write-Output "=== WinHuntAgent service ==="
$svc = Get-Service WinHuntAgent -ErrorAction SilentlyContinue
if ($svc) {
    Write-Output "Service: $($svc.Name) = $($svc.Status)"
    Write-Output "  App: $(nssm get WinHuntAgent Application)"
    Write-Output "  Params: $(nssm get WinHuntAgent AppParameters)"
    Write-Output "  Dir: $(nssm get WinHuntAgent AppDirectory)"
} else { Write-Output "NOT INSTALLED" }

Write-Output "`n=== stderr log ==="
if (Test-Path "C:\DFI\stderr.log") {
    Get-Content "C:\DFI\stderr.log" -Tail 20
} else { Write-Output "No stderr log yet" }

Write-Output "`n=== stdout log ==="
if (Test-Path "C:\DFI\stdout.log") {
    Get-Content "C:\DFI\stdout.log" -Tail 10
} else { Write-Output "No stdout log yet" }
""", "Service status + logs")

# ============================================================
# Cleanup CT112 HTTP server
# ============================================================
pv1_run('pct exec 112 -- bash -c "pkill -f http.server 2>/dev/null; true"')

c.close()
print("\n" + "=" * 60)
print("DEPLOYMENT COMPLETE")
print("=" * 60)
