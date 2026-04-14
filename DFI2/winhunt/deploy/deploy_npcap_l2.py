#!/usr/bin/env python3
"""Deploy Npcap mini package + L2 capture agent to SRV25 via MeshCentral.

Phases:
  0. Probe + cleanup existing Nmap/Npcap on target
  1. Push + install npcap_mini.zip
  2. Ensure pcapy-ng is installed
  3. Deploy updated dfi_agent code + config
  4. Verify L2 capture working

Requires: npcap_mini.zip built by build_npcap_package.py

Usage: python3 deploy/deploy_npcap_l2.py
"""
import io
import json
import os
import sys
import tarfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills"))
from mesh import MeshSession, MESH_IP, MESH_HTTP_PORT

WINHUNT_DIR = "/home/colo8gent/DFI2/winhunt"
NPCAP_ZIP = os.path.join(WINHUNT_DIR, "deploy", "npcap_mini.zip")


TEMP_SCRIPT = r"C:\TEMP\_mc_script.ps1"


def run_ps1(m: MeshSession, ps_code: str, label: str = "", timeout: int = 60) -> str:
    """Run multi-line PS1 on Windows — workaround for ps_file() quoting bug.

    Writes the PS1 to CT112, then uses m.ps() (single-quote safe) to
    download and execute it on Windows.  No single quotes in the download
    command so bash won't choke.
    """
    m._write_ct_file("/tmp/_mc_script.ps1", ps_code)
    m._ensure_http()
    dl_cmd = (
        '$wc = New-Object System.Net.WebClient; '
        f'$wc.DownloadFile("http://{MESH_IP}:{MESH_HTTP_PORT}/_mc_script.ps1","{TEMP_SCRIPT}"); '
        f'& "{TEMP_SCRIPT}"'
    )
    return m.ps(dl_cmd, label=label, timeout=timeout)


def phase0_probe_cleanup(m: MeshSession) -> None:
    """Check and clean up existing Nmap/Npcap installations."""
    print("\n" + "=" * 60)
    print("PHASE 0: Probe + Cleanup existing Npcap/Nmap")
    print("=" * 60)

    # Probe current state
    run_ps1(m, r"""
Write-Output "=== Npcap service ==="
sc.exe query npcap 2>&1

Write-Output "`n=== Npcap directory ==="
if (Test-Path 'C:\Program Files\Npcap') {
    Get-ChildItem 'C:\Program Files\Npcap' -Name
} else { Write-Output "NOT FOUND" }

Write-Output "`n=== System32\Npcap ==="
if (Test-Path 'C:\Windows\System32\Npcap') {
    Get-ChildItem 'C:\Windows\System32\Npcap' -Name
} else { Write-Output "NOT FOUND" }

Write-Output "`n=== Npcap registry ==="
$reg = Get-ItemProperty 'HKLM:\SOFTWARE\Npcap' -ErrorAction SilentlyContinue
if ($reg) { $reg | Format-List } else { Write-Output "NOT FOUND" }

Write-Output "`n=== Nmap ==="
if (Test-Path 'C:\Program Files (x86)\Nmap\nmap.exe') {
    Write-Output "INSTALLED"
} else { Write-Output "NOT FOUND" }

Write-Output "`n=== pcapy import ==="
python -c "import pcapy; print('OK:', pcapy.findalldevs())" 2>&1
""", "Probe existing state")

    # Uninstall Nmap if present (it bundles its own Npcap)
    run_ps1(m, r"""
if (Test-Path 'C:\Program Files (x86)\Nmap\Uninstall.exe') {
    Write-Output "Uninstalling Nmap..."
    & 'C:\Program Files (x86)\Nmap\Uninstall.exe' /S
    Start-Sleep 15
    if (Test-Path 'C:\Program Files (x86)\Nmap\nmap.exe') {
        Write-Output "WARNING: Nmap still present after uninstall"
    } else {
        Write-Output "Nmap removed"
    }
} else {
    Write-Output "Nmap not installed, skipping"
}
""", "Uninstall Nmap")

    # Uninstall existing Npcap
    run_ps1(m, r"""
$uninstaller = 'C:\Program Files\Npcap\Uninstall.exe'
if (Test-Path $uninstaller) {
    Write-Output "Uninstalling Npcap via uninstaller..."
    & $uninstaller /S
    Start-Sleep 10
}

# Force cleanup if remnants remain
$npfInstall = 'C:\Program Files\Npcap\NPFInstall.exe'
if (Test-Path $npfInstall) {
    Write-Output "Running NPFInstall -u..."
    & $npfInstall -u 2>&1
    Start-Sleep 5
}

# Delete service if it lingers
$svc = sc.exe query npcap 2>&1
if ($svc -notmatch 'FAILED') {
    Write-Output "Stopping and deleting npcap service..."
    sc.exe stop npcap 2>&1
    Start-Sleep 2
    sc.exe delete npcap 2>&1
    Start-Sleep 2
}

# Remove directories
if (Test-Path 'C:\Program Files\Npcap') {
    Remove-Item 'C:\Program Files\Npcap' -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output "Removed C:\Program Files\Npcap"
}
if (Test-Path 'C:\Windows\System32\Npcap') {
    Remove-Item 'C:\Windows\System32\Npcap' -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output "Removed C:\Windows\System32\Npcap"
}

# Remove registry key
Remove-Item 'HKLM:\SOFTWARE\Npcap' -Recurse -Force -ErrorAction SilentlyContinue

Write-Output "`n=== Verify clean ==="
$svc2 = sc.exe query npcap 2>&1
if ($svc2 -match 'FAILED') { Write-Output "Service: CLEAN" }
else { Write-Output "WARNING: service still exists" }

if (-not (Test-Path 'C:\Program Files\Npcap')) { Write-Output "Dir Npcap: CLEAN" }
else { Write-Output "WARNING: Npcap dir still exists" }

if (-not (Test-Path 'C:\Windows\System32\Npcap')) { Write-Output "Dir Sys32: CLEAN" }
else { Write-Output "WARNING: Sys32 Npcap dir still exists" }
""", "Uninstall existing Npcap", timeout=60)


def phase1_install_npcap(m: MeshSession) -> None:
    """Push npcap_mini.zip and install driver."""
    print("\n" + "=" * 60)
    print("PHASE 1: Install Npcap mini package")
    print("=" * 60)

    if not os.path.exists(NPCAP_ZIP):
        print(f"ERROR: {NPCAP_ZIP} not found. Run build_npcap_package.py first.")
        sys.exit(1)

    zip_size = os.path.getsize(NPCAP_ZIP)
    print(f"npcap_mini.zip: {zip_size:,} bytes")

    # Upload zip to Windows via CT112
    m.upload_bin(NPCAP_ZIP, r"C:\TEMP\npcap_mini.zip", "Upload npcap_mini.zip")

    # Extract and install
    run_ps1(m, r"""
$ErrorActionPreference = 'Stop'

# Extract zip
Write-Output "Extracting npcap_mini.zip..."
$extractDir = 'C:\TEMP\npcap_extract'
if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
Expand-Archive -Path 'C:\TEMP\npcap_mini.zip' -DestinationPath $extractDir -Force
Get-ChildItem $extractDir -Recurse -Name

# Create target directories
New-Item -ItemType Directory -Force -Path 'C:\Program Files\Npcap' | Out-Null
New-Item -ItemType Directory -Force -Path 'C:\Windows\System32\Npcap' | Out-Null

# Copy Npcap files
Write-Output "`nCopying Npcap driver files..."
$npcapDir = Join-Path $extractDir 'Npcap'
if (Test-Path $npcapDir) {
    Copy-Item "$npcapDir\*" 'C:\Program Files\Npcap\' -Force
    Write-Output "Copied to C:\Program Files\Npcap\"
}

# Copy System32 DLLs
$sys32Dir = Join-Path $extractDir 'System32_Npcap'
if (Test-Path $sys32Dir) {
    Copy-Item "$sys32Dir\*" 'C:\Windows\System32\Npcap\' -Force
    Write-Output "Copied to C:\Windows\System32\Npcap\"
}

# Verify files exist
Write-Output "`n=== Installed files ==="
Get-ChildItem 'C:\Program Files\Npcap' -Name
Get-ChildItem 'C:\Windows\System32\Npcap' -Name
""", "Extract and copy files", timeout=60)

    # Register driver
    # NOTE: NPFInstall.exe excluded — fails on Windows Server 2025.
    # Use netcfg.exe (Windows built-in) which does the same INetCfg registration.
    run_ps1(m, r"""
$ErrorActionPreference = 'Continue'

# Install driver via netcfg (NPFInstall.exe fails on Server 2025)
Write-Output "Installing Npcap driver via netcfg.exe..."
netcfg.exe -l 'C:\Program Files\Npcap\npcap.inf' -c s -i INSECURE_NPCAP 2>&1

Start-Sleep 3

# Set registry values
Write-Output "`nSetting registry..."
New-Item -Path 'HKLM:\SOFTWARE\Npcap' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Npcap' -Name 'WinPcapCompatible' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Npcap' -Name 'AdminOnly' -Value 1 -Type DWord
Write-Output "Registry set"

# Add System32\Npcap to PATH if not already there
$syspath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$npcapPath = 'C:\Windows\System32\Npcap'
if ($syspath -notlike "*$npcapPath*") {
    [Environment]::SetEnvironmentVariable('Path', "$syspath;$npcapPath", 'Machine')
    Write-Output "Added $npcapPath to system PATH"
} else {
    Write-Output "$npcapPath already in PATH"
}

# Refresh current session PATH
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine')

Start-Sleep 2

# Verify driver
Write-Output "`n=== Driver verification ==="
sc.exe query npcap 2>&1
""", "Register Npcap driver", timeout=60)


def phase2_install_pcapy(m: MeshSession) -> None:
    """Ensure pcapy-ng is installed."""
    print("\n" + "=" * 60)
    print("PHASE 2: Install pcapy-ng")
    print("=" * 60)

    run_ps1(m, r"""
# Check if pcapy already works
$test = python -c "import pcapy; print('OK:', pcapy.findalldevs())" 2>&1
Write-Output "pcapy test: $test"

if ($test -like '*OK:*') {
    Write-Output "pcapy-ng already working, skipping install"
} else {
    Write-Output "Installing pcapy-ng..."
    python -m pip install pcapy-ng 2>&1 | Select-Object -Last 5

    # Re-test
    $test2 = python -c "import pcapy; print('OK:', pcapy.findalldevs())" 2>&1
    Write-Output "`nPost-install test: $test2"

    if ($test2 -notlike '*OK:*') {
        Write-Output "WARNING: pcapy-ng install may have failed"
        Write-Output "Agent will fall back to raw socket capture"
    }
}
""", "Install pcapy-ng", timeout=120)


def phase3_deploy_agent(m: MeshSession) -> None:
    """Deploy updated dfi_agent code + config."""
    print("\n" + "=" * 60)
    print("PHASE 3: Deploy updated agent code")
    print("=" * 60)

    # 1. Package agent tarball
    agent_dir = os.path.join(WINHUNT_DIR, "dfi_agent")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(agent_dir, arcname="dfi_agent")
    tarball = buf.getvalue()
    local_tar = "/tmp/dfi_agent.tar.gz"
    with open(local_tar, "wb") as f:
        f.write(tarball)
    print(f"Tarball: {len(tarball):,} bytes")

    # 2. Build config with capture_mode=auto
    config = {
        "vm_id": "WINHUNT-SRV25",
        "mgmt_nic_ip": "172.16.3.160",
        "agent_port": 9200,
        "token": "",
        "buffer_path": r"C:\Program Files\DFI\data\agent_buffer.db",
        "log_dir": r"C:\Program Files\DFI\logs",
        "log_level": "INFO",
        "retention_days": 7,
        "pcap": {
            "interface": "Ethernet0",
            "snap_len": 65535,
            "capture_mode": "auto",
            "flow_timeout_s": 90,
            "max_active_flows": 50000,
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
                "Microsoft-Windows-WMI-Activity/Operational",
            ],
        },
        "exporter": {
            "staging_dir": r"C:\Program Files\DFI\staging",
            "export_interval_s": 30,
            "max_rows_per_file": 10000,
            "retention_hours": 24,
        },
        "services": {
            "rdp": {"ports": [3389], "enabled": True},
            "smb": {"ports": [445], "enabled": True},
            "winrm": {"ports": [5985, 5986], "enabled": True},
            "mssql": {"ports": [1433], "enabled": True},
        },
    }
    config_json = json.dumps(config, indent=2)
    config_path = "/tmp/dfi_config.json"
    with open(config_path, "w") as f:
        f.write(config_json)

    # 3. Upload to CT112
    print("\nUploading to CT112...")
    sftp = m._conn.open_sftp()
    sftp.put(local_tar, "/tmp/dfi_agent.tar.gz")
    sftp.put(config_path, "/tmp/dfi_config.json")
    sftp.close()
    m._pv1("pct push 112 /tmp/dfi_agent.tar.gz /tmp/dfi_agent.tar.gz")
    m._pv1("pct push 112 /tmp/dfi_config.json /tmp/dfi_config.json")
    m._ensure_http()
    print("Files staged on CT112")

    # 4. Stop agent
    m.ps('nssm stop WinHuntAgent 2>$null; Start-Sleep 2; Write-Output "Stopped"',
         "Stop WinHuntAgent")

    # 5. Deploy code + config (use run_ps1 for the complex part)
    #    Raw string for PS1 — never use \\ for Windows paths
    ps_deploy = r"""
$ProgressPreference = "SilentlyContinue"
Remove-Item "C:\Program Files\DFI\data\agent_buffer.db*" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\DFI\stderr.log" -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "C:\TEMP" | Out-Null

$wc = New-Object System.Net.WebClient
$wc.DownloadFile("http://__MESH_IP__:__MESH_PORT__/dfi_agent.tar.gz", "C:\TEMP\dfi_agent.tar.gz")
$size = (Get-Item "C:\TEMP\dfi_agent.tar.gz").Length
Write-Output "Tarball: $size bytes"

python -c "import tarfile,shutil,os; shutil.rmtree(r'C:\Program Files\DFI\agent\dfi_agent', True); os.makedirs(r'C:\Program Files\DFI\agent', exist_ok=True); t=tarfile.open(r'C:\TEMP\dfi_agent.tar.gz'); t.extractall(r'C:\Program Files\DFI\agent'); t.close(); print('extracted')"

$wc.DownloadFile("http://__MESH_IP__:__MESH_PORT__/dfi_config.json", "C:\DFI\config.json")
$files = (Get-ChildItem "C:\Program Files\DFI\agent\dfi_agent" -Filter *.py -ErrorAction SilentlyContinue).Count
Write-Output "Agent files: $files .py"

# Verify capture.py has pcapy support
$cap = Get-Content "C:\Program Files\DFI\agent\dfi_agent\capture.py" -Raw
if ($cap -match "HAS_PCAPY") { Write-Output "capture.py: L2 dual-mode OK" }
else { Write-Output "WARNING: capture.py missing pcapy support" }
""".replace("__MESH_IP__", MESH_IP).replace("__MESH_PORT__", str(MESH_HTTP_PORT))
    run_ps1(m, ps_deploy, "Deploy agent code + config", timeout=90)

    # 6. Start agent
    m.ps('nssm start WinHuntAgent; Start-Sleep 12; Get-Service WinHuntAgent | Format-List Status',
         "Start WinHuntAgent", timeout=30)


def phase4_verify(m: MeshSession) -> None:
    """Verify L2 capture is working."""
    print("\n" + "=" * 60)
    print("PHASE 4: Verify L2 capture")
    print("=" * 60)

    run_ps1(m, r"""
Write-Output "=== agent.log (last 20 lines) ==="
Get-Content "C:\Program Files\DFI\logs\agent.log" -Tail 20 -ErrorAction SilentlyContinue

Write-Output "`n=== Capture mode check ==="
$log = Get-Content "C:\Program Files\DFI\logs\agent.log" -ErrorAction SilentlyContinue
$pcapyLine = $log | Select-String 'pcapy/Npcap'
$rawLine = $log | Select-String 'raw socket'
if ($pcapyLine) {
    Write-Output "L2 MODE: pcapy/Npcap (Ethernet frames with MAC addresses)"
    Write-Output $pcapyLine
} elseif ($rawLine) {
    Write-Output "FALLBACK MODE: raw socket (no MAC addresses)"
    Write-Output $rawLine
} else {
    Write-Output "WARNING: No capture mode line found in log"
}

Write-Output "`n=== stderr ==="
Get-Content "C:\DFI\stderr.log" -Tail 10 -ErrorAction SilentlyContinue

Write-Output "`n=== pcap_flows L2 check ==="
python -c "import sqlite3, os; db = r'C:\Program Files\DFI\data\agent_buffer.db'; print('DB missing') if not os.path.exists(db) else None; conn = sqlite3.connect(db) if os.path.exists(db) else None; rows = conn.execute('SELECT flow_id, src_mac, dst_mac, vlan_id FROM pcap_flows LIMIT 5').fetchall() if conn else []; [print(f'  flow={r[0][:8]}... src_mac={r[1]} dst_mac={r[2]} vlan={r[3]}') for r in rows] if rows else print('No flows yet'); conn.close() if conn else None" 2>&1

Write-Output "`n=== Service status ==="
Get-Service WinHuntAgent | Format-List Name,Status
""", "Verify L2 capture", timeout=30)


def main() -> None:
    print("=" * 60)
    print("DEPLOY NPCAP L2 CAPTURE — SRV25 via MeshCentral")
    print("=" * 60)

    with MeshSession() as m:
        # Quick connectivity check
        m.ps('Write-Output "Connected: $(hostname) at $(Get-Date)"', "Connectivity")

        phase0_probe_cleanup(m)
        phase1_install_npcap(m)
        phase2_install_pcapy(m)
        phase3_deploy_agent(m)
        phase4_verify(m)

        # Cleanup CT112 HTTP server
        m._ct('bash -c "pkill -f \'http.server 8888\' 2>/dev/null; true"')

    print("\n" + "=" * 60)
    print("DEPLOYMENT COMPLETE")
    print("=" * 60)
    print("""
Next steps:
  1. Generate test traffic: python3 skills/run.py 'Test-NetConnection 172.16.3.160 -Port 3389'
  2. View logs: python3 skills/logs.py -n 30
  3. Health check: python3 skills/health.py
""")


if __name__ == "__main__":
    main()
