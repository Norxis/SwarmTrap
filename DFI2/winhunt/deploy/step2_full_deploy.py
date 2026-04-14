#!/usr/bin/env python3
"""
Step 2+3: Install MeshAgent on Windows, then use MeshCentral to deploy
the full DFI agent stack (Python, Npcap, NSSM, dfi_agent, service).
"""
import paramiko
import winrm
import time
import re
import json
import base64
import sys
import os

PV1 = "192.168.0.100"
PV1_USER = "root"
PV1_PASS = "CHANGE_ME"
MESH_USER = "admin"
MESH_PASS = "CHANGE_ME"
MESH_IP = "172.16.3.112"

WIN_HOST = "http://172.16.3.160:5985/wsman"
WIN_USER = "Administrator"
WIN_PASS = "CHANGE_ME"

MESHCTRL = "/opt/meshcentral/node_modules/meshcentral/meshctrl.js"
MBASE = f'--url wss://localhost --loginuser {MESH_USER} --loginpass "{MESH_PASS}"'


def pv1_run(client, cmd, timeout=120):
    print(f"\n[PV1] $ {cmd[:200]}")
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    rc = stdout.channel.recv_exit_status()
    if out:
        for line in out.split("\n")[-25:]:
            print(f"  {line}")
    if rc != 0 and err:
        print(f"  ERR(rc={rc}): {err[:400]}")
    return out, err, rc


def win_run(script, label="", timeout=120):
    if label:
        print(f"\n[WIN-WinRM] [{label}]")
    s = winrm.Session(WIN_HOST, auth=(WIN_USER, WIN_PASS), transport="ntlm",
                      read_timeout_sec=timeout+30, operation_timeout_sec=timeout)
    r = s.run_ps(script)
    out = r.std_out.decode("utf-8", errors="replace").strip()
    err_raw = r.std_err.decode("utf-8", errors="replace").strip()
    err = "\n".join(
        l for l in err_raw.split("\n")
        if not any(x in l for x in ["<Obj", "CLIXML", "Preparing modules", "<TNRef", "<MS>", "<I64", "<PR ", "</Obj", "</MS", "<TN ", "<T>"])
        and l.strip()
    )
    if out:
        for line in out.split("\n")[-25:]:
            print(f"  {line}")
    if r.status_code != 0 and err:
        print(f"  ERR: {err[:400]}")
    return out, err, r.status_code


def mesh_run(pv1, node_id, ps_script, label="", timeout=120):
    """Run PowerShell on remote Windows via MeshCentral."""
    if label:
        print(f"\n[MESH-CMD] [{label}]")
    # Escape for shell
    ps_b64 = base64.b64encode(ps_script.encode("utf-16-le")).decode()
    cmd = f'pct exec 112 -- node {MESHCTRL} {MBASE} runcommand --id "{node_id}" --run "powershell -EncodedCommand {ps_b64}" 2>&1'
    return pv1_run(pv1, cmd, timeout=timeout)


def main():
    pv1 = paramiko.SSHClient()
    pv1.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pv1.connect(PV1, username=PV1_USER, password=PV1_PASS, timeout=10)

    # ================================================================
    # PHASE 1: Bootstrap MeshAgent via WinRM
    # ================================================================
    print("=" * 60)
    print("PHASE 1: Install MeshAgent via WinRM")
    print("=" * 60)

    # Get mesh ID
    out, _, _ = pv1_run(pv1, f'pct exec 112 -- node {MESHCTRL} {MBASE} listdevicegroups 2>&1')
    mesh_id = None
    for line in out.split("\n"):
        if "WinHunt-Test" in line:
            match = re.search(r'"([^"]+)".*WinHunt-Test', line)
            if match:
                mesh_id = match.group(1)
    if not mesh_id:
        print("Creating device group...")
        out, _, _ = pv1_run(pv1, f'pct exec 112 -- node {MESHCTRL} {MBASE} adddevicegroup --name "WinHunt-Test" 2>&1')
        match = re.search(r'mesh//(\S+)', out)
        if match:
            mesh_id = match.group(1)
    print(f"  Mesh ID: {mesh_id}")

    # Get server cert hash
    out, _, _ = pv1_run(pv1, 'pct exec 112 -- openssl x509 -in /opt/meshcentral/meshcentral-data/webserver-cert-public.crt -fingerprint -sha384 -noout 2>/dev/null')
    hash_match = re.search(r'=([A-Fa-f0-9:]+)', out)
    server_hash = hash_match.group(1).replace(":", "").upper() if hash_match else ""
    print(f"  Server hash: {server_hash[:40]}...")

    # Check if MeshAgent already installed on Windows
    out, _, rc = win_run("""
        $svc = Get-Service | Where-Object { $_.Name -like "*mesh*" -or $_.DisplayName -like "*mesh*" }
        if ($svc) { Write-Output "INSTALLED: $($svc.Name) = $($svc.Status)" }
        else { Write-Output "NOT_INSTALLED" }
    """, "Check MeshAgent")

    if "NOT_INSTALLED" in out:
        # Download agent binary from MeshCentral
        win_run(f"""
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {{
    add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {{
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) {{ return true; }}
}}
"@
}}
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
$wc = New-Object System.Net.WebClient
$wc.DownloadFile("https://{MESH_IP}/meshagents?id=4", "$env:TEMP\\meshagent.exe")
Write-Output "Agent: $((Get-Item "$env:TEMP\\meshagent.exe").Length) bytes"
        """, "Download MeshAgent", timeout=60)

        # Write MSH
        msh = f"MeshName=WinHunt MeshCentral\nMeshType=2\nMeshID=0x{mesh_id}\nServerID={server_hash}\nMeshServer=wss://{MESH_IP}:443/agent.ashx"
        win_run(f"""
@'
{msh}
'@ | Set-Content -Path "$env:TEMP\\meshagent.msh" -Encoding ASCII -NoNewline
Write-Output "MSH written"
Get-Content "$env:TEMP\\meshagent.msh"
        """, "Write MSH")

        # Install
        win_run(r"""
$installDir = "C:\Program Files\Mesh Agent"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item "$env:TEMP\meshagent.exe" "$installDir\MeshAgent.exe" -Force
Copy-Item "$env:TEMP\meshagent.msh" "$installDir\MeshAgent.msh" -Force
Start-Process -FilePath "$installDir\MeshAgent.exe" -ArgumentList "-install" -Wait -NoNewWindow
Start-Sleep -Seconds 8
$svc = Get-Service | Where-Object { $_.Name -like "*mesh*" }
if ($svc) { Write-Output "OK: $($svc.Name) = $($svc.Status)" }
else {
    Write-Output "Service not found, checking processes..."
    Get-Process | Where-Object { $_.Name -like "*mesh*" } | ForEach-Object { Write-Output "  PID $($_.Id): $($_.Name)" }
}
        """, "Install MeshAgent", timeout=30)
    else:
        print("  MeshAgent already installed, skipping.")

    # Wait for agent to connect
    print("\n  Waiting 15s for agent to connect to MeshCentral...")
    time.sleep(15)

    # Get node ID from MeshCentral
    out, _, _ = pv1_run(pv1, f'pct exec 112 -- node {MESHCTRL} {MBASE} listdevices --group "WinHunt-Test" 2>&1')
    node_id = None
    for line in out.split("\n"):
        line = line.strip()
        if line and not line.startswith("id") and not line.startswith("--"):
            match = re.search(r'"([^"]+)"', line)
            if match:
                node_id = match.group(1)
                break

    if not node_id:
        print("\n  Agent not showing in MeshCentral yet. Waiting 15 more seconds...")
        time.sleep(15)
        out, _, _ = pv1_run(pv1, f'pct exec 112 -- node {MESHCTRL} {MBASE} listdevices --group "WinHunt-Test" 2>&1')
        for line in out.split("\n"):
            line = line.strip()
            if line and not line.startswith("id") and not line.startswith("--"):
                match = re.search(r'"([^"]+)"', line)
                if match:
                    node_id = match.group(1)
                    break

    if not node_id:
        print("WARNING: Could not get node ID. Will continue with WinRM for remaining steps.")
        use_mesh = False
    else:
        print(f"\n  Node ID: {node_id}")
        use_mesh = True

        # Quick test — run command via MeshCentral
        mesh_run(pv1, node_id, "Write-Output \"Hello from MeshCentral! Hostname: $env:COMPUTERNAME\"", "Test command")

    # ================================================================
    # PHASE 2: Deploy full stack via MeshCentral (or WinRM fallback)
    # ================================================================
    print("\n" + "=" * 60)
    print("PHASE 2: Deploy DFI agent stack")
    print("=" * 60)

    def run_on_win(ps, label="", timeout=120):
        """Run PS on Windows via MeshCentral if available, else WinRM."""
        if use_mesh:
            return mesh_run(pv1, node_id, ps, label, timeout)
        else:
            return win_run(ps, label, timeout)

    # --- 2a: Install Python 3.12 ---
    out, _, _ = run_on_win("""
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
try { $v = python --version 2>&1; Write-Output "PYTHON_OK: $v" } catch { Write-Output "PYTHON_MISSING" }
    """, "Check Python")

    if "PYTHON_MISSING" in out or "not found" in out.lower() or "not recognized" in out.lower():
        run_on_win("""
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$url = "https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe"
Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\\python-installer.exe" -UseBasicParsing
Start-Process -FilePath "$env:TEMP\\python-installer.exe" -ArgumentList "/quiet","InstallAllUsers=1","PrependPath=1","Include_pip=1","Include_test=0" -Wait
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
python --version
python -m pip install --upgrade pip 2>&1 | Select-Object -Last 2
Write-Output "PYTHON_INSTALLED"
        """, "Install Python 3.12", timeout=300)
    else:
        print("  Python already installed.")

    # --- 2b: Install NSSM ---
    out, _, _ = run_on_win("""
if (Test-Path "C:\\Windows\\System32\\nssm.exe") { Write-Output "NSSM_OK" } else { Write-Output "NSSM_MISSING" }
    """, "Check NSSM")

    if "NSSM_MISSING" in out:
        run_on_win("""
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile "$env:TEMP\\nssm.zip" -UseBasicParsing
Expand-Archive -Path "$env:TEMP\\nssm.zip" -DestinationPath "$env:TEMP" -Force
Copy-Item "$env:TEMP\\nssm-2.24\\win64\\nssm.exe" "C:\\Windows\\System32\\nssm.exe" -Force
Write-Output "NSSM_INSTALLED"
        """, "Install NSSM", timeout=60)

    # --- 2c: Install Npcap ---
    out, _, _ = run_on_win("""
if (Test-Path "C:\\Program Files\\Npcap\\npcap.sys") { Write-Output "NPCAP_OK" } else { Write-Output "NPCAP_MISSING" }
    """, "Check Npcap")

    if "NPCAP_MISSING" in out:
        run_on_win("""
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$url = "https://npcap.com/dist/npcap-1.80.exe"
Write-Output "Downloading Npcap..."
try {
    Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\\npcap.exe" -UseBasicParsing -TimeoutSec 120
} catch {
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($url, "$env:TEMP\\npcap.exe")
}
Write-Output "Downloaded: $((Get-Item "$env:TEMP\\npcap.exe").Length) bytes"
Start-Process -FilePath "$env:TEMP\\npcap.exe" -ArgumentList "/S","/winpcap_mode=yes","/loopback_support=yes" -Wait
Start-Sleep -Seconds 3
if (Test-Path "C:\\Program Files\\Npcap\\npcap.sys") { Write-Output "NPCAP_INSTALLED" }
else { Write-Output "NPCAP_INSTALL_WARNING" }
        """, "Install Npcap", timeout=180)

    # --- 2d: Install pip packages ---
    run_on_win("""
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
python -m pip install pcapy-ng pywin32 2>&1 | Select-Object -Last 5
Write-Output "PIP_DONE"
    """, "Install pip packages", timeout=120)

    # --- 2e: Deploy dfi_agent code ---
    print("\n  Transferring dfi_agent package...")
    # Create tarball and base64 encode
    agent_dir = os.path.expanduser("~/DFI2/winhunt")
    os.system(f"cd {agent_dir} && tar czf /tmp/dfi_agent.tar.gz dfi_agent/")
    with open("/tmp/dfi_agent.tar.gz", "rb") as f:
        b64 = base64.b64encode(f.read()).decode()
    print(f"  Package: {len(b64)} base64 chars")

    # Create directories
    run_on_win(r"""
$dirs = @("C:\Program Files\DFI\agent","C:\Program Files\DFI\data","C:\Program Files\DFI\logs","C:\Program Files\DFI\staging")
foreach ($d in $dirs) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
Write-Output "Directories created"
    """, "Create DFI dirs")

    # Transfer in chunks via WinRM (MeshCentral runcommand has size limits)
    chunk_size = 25000
    chunks = [b64[i:i+chunk_size] for i in range(0, len(b64), chunk_size)]
    print(f"  Sending {len(chunks)} chunks...")

    for i, chunk in enumerate(chunks):
        mode = "Set" if i == 0 else "Add"
        win_run(f"""
{mode}-Content -Path "$env:TEMP\\dfi_b64.txt" -Value '{chunk}' -NoNewline
        """, f"chunk {i+1}/{len(chunks)}")

    # Decode and extract
    win_run(r"""
$b64 = Get-Content "$env:TEMP\dfi_b64.txt" -Raw
$bytes = [System.Convert]::FromBase64String($b64)
[System.IO.File]::WriteAllBytes("$env:TEMP\dfi_agent.tar.gz", $bytes)
Write-Output "Decoded: $($bytes.Length) bytes"
cd $env:TEMP
tar xzf dfi_agent.tar.gz
Copy-Item -Recurse -Force "$env:TEMP\dfi_agent" "C:\Program Files\DFI\agent\"
$count = (Get-ChildItem "C:\Program Files\DFI\agent\dfi_agent" -Recurse -File).Count
Write-Output "Deployed $count files"
    """, "Extract agent code")

    # --- 2f: Write config.json ---
    config = {
        "vm_id": "WINHUNT-TEST",
        "mgmt_nic_ip": "172.16.3.160",
        "agent_port": 9200,
        "token": "",
        "buffer_path": r"C:\Program Files\DFI\data\agent_buffer.db",
        "log_dir": r"C:\Program Files\DFI\logs",
        "log_level": "INFO",
        "retention_days": 7,
        "pcap": {
            "enabled": True, "interface": "Ethernet0", "snap_len": 256,
            "buffer_mb": 16, "bpf_filter": "", "flow_timeout_s": 120,
            "flow_drain_rst_s": 2, "flow_drain_fin_s": 5,
            "max_active_flows": 50000, "max_event_pkts": 128,
            "max_flow_pkts": 10000, "capture_source": 1,
            "local_networks": ["172.16.3.0/24", "192.168.0.0/24"]
        },
        "evidence": {
            "enabled": True,
            "channels": [
                "Security", "System", "Application",
                "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
                "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
                "Microsoft-Windows-WinRM/Operational",
                "Microsoft-Windows-PowerShell/Operational",
                "Microsoft-Windows-Windows Defender/Operational",
                "Microsoft-Windows-Sysmon/Operational"
            ],
            "iis_log_dir": r"C:\inetpub\logs\LogFiles\W3SVC1",
            "logon_map_ttl_hours": 24,
            "suspicious_patterns": [r"(cmd|powershell|pwsh).*(/c|/k|-enc|-e\s)"],
            "download_patterns": [r"(certutil)\s.*-urlcache"]
        },
        "exporter": {
            "enabled": True, "staging_dir": r"C:\Program Files\DFI\staging",
            "export_interval_s": 30, "max_rows_per_file": 10000,
            "file_prefix": "dfi", "retention_hours": 24
        },
        "services": [
            {"name": "rdp", "ports": [3389], "enabled": True},
            {"name": "smb", "ports": [445], "enabled": True},
            {"name": "winrm", "ports": [5985, 5986], "enabled": True}
        ]
    }
    config_json = json.dumps(config, indent=2)
    win_run(f"""
@'
{config_json}
'@ | Set-Content -Path 'C:\\Program Files\\DFI\\config.json' -Encoding UTF8
$ch = (Get-Content 'C:\\Program Files\\DFI\\config.json' | ConvertFrom-Json).evidence.channels.Count
Write-Output "Config written: $ch channels"
    """, "Write config.json")

    # --- 2g: Configure audit policies ---
    run_on_win(r"""
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Process Termination" /success:enable
auditpol /set /subcategory:"Security System Extension" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
wevtutil sl Security /ms:134217728
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:67108864
Write-Output "Audit policies configured"
    """, "Configure audit policies")

    # --- 2h: Create and start WinHunt service via NSSM ---
    run_on_win(r"""
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
$svcName = "WinHuntAgent"

# Remove if exists
$existing = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($existing) {
    nssm stop $svcName 2>$null
    nssm remove $svcName confirm 2>$null
    Start-Sleep -Seconds 2
}

$py = (Get-Command python).Source
nssm install $svcName $py "-m" "dfi_agent" "--config" "C:\Program Files\DFI\config.json"
nssm set $svcName AppDirectory "C:\Program Files\DFI\agent"
nssm set $svcName DisplayName "WinHunt DFI Agent"
nssm set $svcName Description "DFI Windows capture agent"
nssm set $svcName Start SERVICE_AUTO_START
nssm set $svcName AppStdout "C:\Program Files\DFI\logs\service_stdout.log"
nssm set $svcName AppStderr "C:\Program Files\DFI\logs\service_stderr.log"
nssm set $svcName AppRotateFiles 1
nssm set $svcName AppRotateBytes 10485760
nssm start $svcName
Start-Sleep -Seconds 5
$svc = Get-Service -Name $svcName
Write-Output "Service $svcName = $($svc.Status)"
    """, "Create WinHunt service")

    # ================================================================
    # PHASE 3: Final verification
    # ================================================================
    print("\n" + "=" * 60)
    print("PHASE 3: Verification")
    print("=" * 60)

    win_run(r"""
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

Write-Output "=== Python ===" ; python --version
Write-Output "=== Npcap ===" ; if (Test-Path "C:\Program Files\Npcap\npcap.sys") { "OK" } else { "MISSING" }
Write-Output "=== NSSM ===" ; if (Test-Path "C:\Windows\System32\nssm.exe") { "OK" } else { "MISSING" }
Write-Output "=== Agent files ==="
(Get-ChildItem "C:\Program Files\DFI\agent\dfi_agent" -File).Name | Sort-Object
Write-Output "=== Config ==="
$c = Get-Content "C:\Program Files\DFI\config.json" | ConvertFrom-Json
Write-Output "  vm_id=$($c.vm_id) channels=$($c.evidence.channels.Count) interface=$($c.pcap.interface)"
Write-Output "=== Services ==="
Get-Service WinHuntAgent,*mesh* -ErrorAction SilentlyContinue | Format-Table Name, Status, StartType -AutoSize
Write-Output "=== Agent log (last 10) ==="
if (Test-Path "C:\Program Files\DFI\logs\agent.log") { Get-Content "C:\Program Files\DFI\logs\agent.log" -Tail 10 }
elseif (Test-Path "C:\Program Files\DFI\logs\service_stderr.log") {
    Write-Output "(from stderr)"
    Get-Content "C:\Program Files\DFI\logs\service_stderr.log" -Tail 10
} else { "No logs yet" }
    """, "Final verification")

    # Check from MeshCentral
    pv1_run(pv1, f'pct exec 112 -- node {MESHCTRL} {MBASE} listdevices --group "WinHunt-Test" 2>&1', timeout=30)

    pv1.close()
    print("\n" + "=" * 60)
    print("DEPLOYMENT COMPLETE")
    print("  MeshCentral: https://172.16.3.112 (admin/CHANGE_ME)")
    print("  WinHunt agent: 172.16.3.160 (WinHuntAgent service)")
    print("=" * 60)


if __name__ == "__main__":
    main()
