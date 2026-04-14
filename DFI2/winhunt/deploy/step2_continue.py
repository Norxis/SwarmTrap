#!/usr/bin/env python3
"""
Continue deployment:
1. Fix MeshAgent MSH (proper install via invite link)
2. Serve dfi_agent tarball from CT112 for Windows to download
3. Complete agent setup
"""
import paramiko
import winrm
import time
import re
import json
import base64
import os
import sys

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
        print(f"\n[WIN] [{label}]")
    s = winrm.Session(WIN_HOST, auth=(WIN_USER, WIN_PASS), transport="ntlm",
                      read_timeout_sec=timeout+30, operation_timeout_sec=timeout)
    r = s.run_ps(script)
    out = r.std_out.decode("utf-8", errors="replace").strip()
    err_raw = r.std_err.decode("utf-8", errors="replace").strip()
    err = "\n".join(
        l for l in err_raw.split("\n")
        if not any(x in l for x in ["<Obj", "CLIXML", "Preparing modules", "<TNRef",
                                     "<MS>", "<I64", "<PR ", "</Obj", "</MS", "<TN ", "<T>"])
        and l.strip()
    )
    if out:
        for line in out.split("\n")[-25:]:
            print(f"  {line}")
    if r.status_code != 0 and err:
        print(f"  ERR: {err[:400]}")
    return out, err, r.status_code


def main():
    pv1 = paramiko.SSHClient()
    pv1.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pv1.connect(PV1, username=PV1_USER, password=PV1_PASS, timeout=10)

    # ================================================================
    # FIX 1: Reinstall MeshAgent with proper invite URL
    # ================================================================
    print("=" * 60)
    print("FIX 1: Reinstall MeshAgent via MeshCentral invite URL")
    print("=" * 60)

    # Get the proper agent install script from MeshCentral
    # This embeds the correct MSH data automatically
    out, _, _ = pv1_run(pv1, f'pct exec 112 -- node {MESHCTRL} {MBASE} listdevicegroups --json 2>&1')

    # Get mesh hex id for URL
    mesh_id = None
    for line in out.split("\n"):
        if "WinHunt-Test" in line:
            match = re.search(r'"([^"]+)".*WinHunt-Test', line)
            if match:
                mesh_id = match.group(1)
    if not mesh_id:
        # Try JSON parse
        try:
            groups = json.loads(out)
            for g in groups:
                if "WinHunt-Test" in str(g):
                    mesh_id = g.get("_id", "").split("/")[-1]
        except:
            pass

    print(f"  Mesh ID: {mesh_id}")

    # Uninstall existing broken agent first
    win_run(r"""
$agentExe = "C:\Program Files\Mesh Agent\MeshAgent.exe"
if (Test-Path $agentExe) {
    Start-Process -FilePath $agentExe -ArgumentList "-uninstall" -Wait -NoNewWindow
    Start-Sleep -Seconds 3
    Write-Output "Uninstalled existing MeshAgent"
} else {
    Write-Output "No existing agent found"
}
# Also check for mesh service
$svc = Get-Service | Where-Object { $_.Name -like "*mesh*" }
if ($svc) {
    Stop-Service $svc.Name -Force -ErrorAction SilentlyContinue
    sc.exe delete $svc.Name 2>$null
    Write-Output "Removed service: $($svc.Name)"
}
    """, "Uninstall old MeshAgent")

    # Get the install script that MeshCentral generates
    # This is the proper way — it includes correct MSH embedded
    out, _, _ = pv1_run(pv1,
        f'pct exec 112 -- curl -sk "https://localhost/meshagents?script=1&meshid=mesh//{mesh_id}" 2>/dev/null | head -30')
    print(f"  Install script from MC (first 200 chars): {out[:200]}")

    # Alternative: use the meshaction.txt approach
    # Download the raw MSH that MeshCentral generates for this group
    out, _, _ = pv1_run(pv1,
        f'pct exec 112 -- curl -sk "https://localhost/meshagents?meshinstall=10&meshid=mesh//{mesh_id}" -o /tmp/meshagent_win64.exe -w "size=%{{size_download}}" 2>/dev/null')

    # Check: did we get a real binary?
    out, _, _ = pv1_run(pv1, 'pct exec 112 -- ls -la /tmp/meshagent_win64.exe 2>/dev/null')

    # The ?meshinstall=10 URL returns a Windows agent with MSH embedded
    # meshinstall values: 4=win32, 10=win64 (with MSH embedded)
    if "meshagent_win64" in out:
        size = int(re.search(r'(\d+)\s+\w+\s+\d+\s+\d+:\d+\s+/tmp/meshagent_win64', out).group(1)) if re.search(r'(\d+)\s+\w+\s+\d+\s+\d+:\d+\s+/tmp/meshagent_win64', out) else 0
        print(f"  Agent binary (with embedded MSH): {size} bytes")

        if size > 1000000:
            # Good — we have a proper embedded agent. Serve it from CT112.
            # Start temp HTTP server on CT112 port 8888
            pv1_run(pv1, 'pct exec 112 -- bash -c "pkill -f SimpleHTTPServer 2>/dev/null; pkill -f http.server 2>/dev/null; true"')
            pv1_run(pv1, 'pct exec 112 -- bash -c "cd /tmp && python3 -m http.server 8888 &" 2>&1')
            time.sleep(2)

            # Download on Windows from CT112
            win_run(f"""
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$wc = New-Object System.Net.WebClient
$wc.DownloadFile("http://{MESH_IP}:8888/meshagent_win64.exe", "$env:TEMP\\meshagent_embedded.exe")
$size = (Get-Item "$env:TEMP\\meshagent_embedded.exe").Length
Write-Output "Downloaded embedded agent: $size bytes"
            """, "Download embedded agent", timeout=60)

            # Install
            win_run(r"""
$installDir = "C:\Program Files\Mesh Agent"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item "$env:TEMP\meshagent_embedded.exe" "$installDir\MeshAgent.exe" -Force
Start-Process -FilePath "$installDir\MeshAgent.exe" -ArgumentList "-install" -Wait -NoNewWindow
Start-Sleep -Seconds 10
$svc = Get-Service | Where-Object { $_.Name -like "*mesh*" }
if ($svc) { Write-Output "Service: $($svc.Name) = $($svc.Status)" }
else { Write-Output "NO MESH SERVICE FOUND" }
            """, "Install embedded agent")

            # Kill temp HTTP server
            pv1_run(pv1, 'pct exec 112 -- bash -c "pkill -f http.server 2>/dev/null; true"')

    # Wait and check if agent connected
    print("\n  Waiting 20s for agent to connect...")
    time.sleep(20)
    out, _, _ = pv1_run(pv1, f'pct exec 112 -- node {MESHCTRL} {MBASE} listdevices --group "WinHunt-Test" 2>&1')

    node_id = None
    for line in out.split("\n"):
        line = line.strip()
        if line and not line.startswith("id") and not line.startswith("--") and line != "None":
            match = re.search(r'"([^"]+)"', line)
            if match:
                node_id = match.group(1)
                break

    if node_id:
        print(f"\n  Agent connected! Node ID: {node_id}")
    else:
        print("\n  Agent still not visible. Checking agent log on Windows...")
        win_run(r"""
if (Test-Path "C:\Program Files\Mesh Agent\MeshAgent.log") {
    Get-Content "C:\Program Files\Mesh Agent\MeshAgent.log" -Tail 20
} else {
    Get-ChildItem "C:\Program Files\Mesh Agent" -Name
}
        """, "Agent logs")

    # ================================================================
    # FIX 2: Transfer dfi_agent via HTTP from CT112
    # ================================================================
    print("\n" + "=" * 60)
    print("FIX 2: Transfer dfi_agent via HTTP")
    print("=" * 60)

    # Create tarball
    agent_dir = os.path.expanduser("~/DFI2/winhunt")
    os.system(f"cd {agent_dir} && tar czf /tmp/dfi_agent.tar.gz dfi_agent/")
    tarball_size = os.path.getsize("/tmp/dfi_agent.tar.gz")
    print(f"  Tarball: {tarball_size} bytes")

    # SCP to CT112 via PV1 (push into LXC)
    # First copy to PV1, then into LXC
    sftp = pv1.open_sftp()
    sftp.put("/tmp/dfi_agent.tar.gz", "/tmp/dfi_agent.tar.gz")
    sftp.close()
    print("  Uploaded to PV1:/tmp/")

    pv1_run(pv1, "pct push 112 /tmp/dfi_agent.tar.gz /tmp/dfi_agent.tar.gz")
    print("  Pushed into CT112:/tmp/")

    # Serve via HTTP
    pv1_run(pv1, 'pct exec 112 -- bash -c "pkill -f http.server 2>/dev/null; cd /tmp && python3 -m http.server 8888 &"')
    time.sleep(2)

    # Download on Windows
    win_run(f"""
$ProgressPreference = "SilentlyContinue"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile("http://{MESH_IP}:8888/dfi_agent.tar.gz", "$env:TEMP\\dfi_agent.tar.gz")
Write-Output "Downloaded: $((Get-Item "$env:TEMP\\dfi_agent.tar.gz").Length) bytes"
cd $env:TEMP
tar xzf dfi_agent.tar.gz
Copy-Item -Recurse -Force "$env:TEMP\\dfi_agent" "C:\\Program Files\\DFI\\agent\\"
$count = (Get-ChildItem "C:\\Program Files\\DFI\\agent\\dfi_agent" -Recurse -File).Count
Write-Output "Deployed $count files to C:\\Program Files\\DFI\\agent\\dfi_agent"
    """, "Download + extract agent code", timeout=60)

    # Kill temp HTTP server
    pv1_run(pv1, 'pct exec 112 -- bash -c "pkill -f http.server 2>/dev/null; true"')

    # ================================================================
    # REMAINING: Npcap, config, audit, service
    # ================================================================
    print("\n" + "=" * 60)
    print("REMAINING SETUP")
    print("=" * 60)

    # Check Npcap status
    out, _, _ = win_run("""
if (Test-Path "C:\\Program Files\\Npcap\\npcap.sys") { Write-Output "NPCAP_OK" }
elseif (Test-Path "C:\\Program Files\\Npcap") {
    Write-Output "NPCAP_DIR_EXISTS"
    Get-ChildItem "C:\\Program Files\\Npcap" -Name
}
else { Write-Output "NPCAP_MISSING" }
    """, "Check Npcap")

    if "NPCAP_OK" not in out:
        # Serve npcap from CT112 too
        pv1_run(pv1, f'pct exec 112 -- bash -c "curl -sLo /tmp/npcap.exe https://npcap.com/dist/npcap-1.80.exe && ls -la /tmp/npcap.exe"', timeout=120)
        pv1_run(pv1, 'pct exec 112 -- bash -c "cd /tmp && python3 -m http.server 8888 &"')
        time.sleep(2)

        win_run(f"""
$ProgressPreference = "SilentlyContinue"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile("http://{MESH_IP}:8888/npcap.exe", "$env:TEMP\\npcap.exe")
Write-Output "Downloaded: $((Get-Item "$env:TEMP\\npcap.exe").Length) bytes"
Start-Process -FilePath "$env:TEMP\\npcap.exe" -ArgumentList "/S","/winpcap_mode=yes","/loopback_support=yes" -Wait
Start-Sleep -Seconds 5
if (Test-Path "C:\\Program Files\\Npcap\\npcap.sys") {{ Write-Output "NPCAP_INSTALLED" }}
else {{ Write-Output "NPCAP_FAILED" }}
        """, "Install Npcap via HTTP", timeout=180)

        pv1_run(pv1, 'pct exec 112 -- bash -c "pkill -f http.server 2>/dev/null; true"')

    # Write config.json
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
Write-Output "Config: $ch channels"
    """, "Write config.json")

    # Audit policies
    win_run(r"""
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
Write-Output "Audit configured"
    """, "Audit policies")

    # Create WinHunt service
    win_run(r"""
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
$svcName = "WinHuntAgent"
$existing = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($existing) {
    nssm stop $svcName 2>$null
    nssm remove $svcName confirm 2>$null
    Start-Sleep -Seconds 2
}
$py = (Get-Command python).Source
nssm install $svcName $py "-m" "dfi_agent" "--config" "`"C:\Program Files\DFI\config.json`""
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
Write-Output "Service: $svcName = $($svc.Status)"
    """, "Create WinHunt service")

    # ================================================================
    # FINAL VERIFICATION
    # ================================================================
    print("\n" + "=" * 60)
    print("FINAL VERIFICATION")
    print("=" * 60)

    win_run(r"""
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
Write-Output "=== Python ===" ; python --version
Write-Output "=== Npcap ===" ; if (Test-Path "C:\Program Files\Npcap\npcap.sys") { "OK" } else { "MISSING" }
Write-Output "=== NSSM ===" ; if (Test-Path "C:\Windows\System32\nssm.exe") { "OK" } else { "MISSING" }
Write-Output "=== MeshAgent ==="
Get-Service | Where-Object { $_.Name -like "*mesh*" } | ForEach-Object { "$($_.Name) = $($_.Status)" }
Write-Output "=== Agent files ==="
(Get-ChildItem "C:\Program Files\DFI\agent\dfi_agent" -File -ErrorAction SilentlyContinue).Name | Sort-Object
Write-Output "=== Config ==="
$c = Get-Content "C:\Program Files\DFI\config.json" -ErrorAction SilentlyContinue | ConvertFrom-Json
if ($c) { "vm_id=$($c.vm_id) channels=$($c.evidence.channels.Count) nic=$($c.pcap.interface)" }
Write-Output "=== Services ==="
Get-Service WinHuntAgent -ErrorAction SilentlyContinue | Format-Table Name, Status, StartType -AutoSize
Write-Output "=== Logs ==="
if (Test-Path "C:\Program Files\DFI\logs\service_stderr.log") { Get-Content "C:\Program Files\DFI\logs\service_stderr.log" -Tail 15 }
elseif (Test-Path "C:\Program Files\DFI\logs\agent.log") { Get-Content "C:\Program Files\DFI\logs\agent.log" -Tail 15 }
else { "No logs yet" }
    """, "Final check")

    # Check from MeshCentral
    pv1_run(pv1, f'pct exec 112 -- node {MESHCTRL} {MBASE} listdevices --group "WinHunt-Test" 2>&1')

    pv1.close()
    print("\n" + "=" * 60)
    print("DEPLOYMENT COMPLETE")
    print("  MeshCentral: https://172.16.3.112 (admin/CHANGE_ME)")
    print("  WinHunt agent: 172.16.3.160 (WinHuntAgent service)")
    print("=" * 60)


if __name__ == "__main__":
    main()
