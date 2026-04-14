#!/usr/bin/env python3
"""
Finish deployment — MeshAgent reinstall, file transfer via HTTP, Npcap, config, service.
HTTP server already running on CT112:8888 serving /tmp/.
"""
import paramiko
import winrm
import time
import json
import os
import sys

MESH_IP = "172.16.3.112"
MESH_ID = "QZAw0650tLTtoYRtd4ahevqStGXHSW6FlRqOdUTKKGTnLMZhIq4Drc26ep50q$AI"

PV1 = "192.168.0.100"
PV1_USER = "root"
PV1_PASS = "CHANGE_ME"

WIN_HOST = "http://172.16.3.160:5985/wsman"
WIN_USER = "Administrator"
WIN_PASS = "CHANGE_ME"


def win_run(script, label="", timeout=120):
    if label:
        print(f"\n[{label}]")
    s = winrm.Session(WIN_HOST, auth=(WIN_USER, WIN_PASS), transport="ntlm",
                      read_timeout_sec=timeout+30, operation_timeout_sec=timeout)
    r = s.run_ps(script)
    out = r.std_out.decode("utf-8", errors="replace").strip()
    if out:
        for line in out.split("\n")[-25:]:
            print(f"  {line}")
    if r.status_code != 0:
        err_raw = r.std_err.decode("utf-8", errors="replace")
        err = "\n".join(l for l in err_raw.split("\n")
                        if not any(x in l for x in ["<Obj", "CLIXML", "<TN", "<MS>", "<I64", "<PR ", "</", "progress"])
                        and l.strip())
        if err:
            print(f"  ERR: {err[:400]}")
    return out, r.status_code


def main():
    # ================================================================
    # STEP A: Reinstall MeshAgent with proper embedded MSH
    # ================================================================
    print("=" * 60)
    print("STEP A: Reinstall MeshAgent (embedded MSH from CT112)")
    print("=" * 60)

    # Get the embedded agent from MeshCentral
    pv1 = paramiko.SSHClient()
    pv1.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pv1.connect(PV1, username=PV1_USER, password=PV1_PASS, timeout=10)

    # Download agent with embedded MSH using correct mesh ID
    full_mesh_id = f"mesh//{MESH_ID}"
    cmd = f'pct exec 112 -- curl -sk "https://localhost/meshagents?meshinstall=10&meshid={full_mesh_id}" -o /tmp/meshagent_win64.exe -w "%{{size_download}}"'
    stdin, stdout, stderr = pv1.exec_command(cmd, timeout=30)
    size_str = stdout.read().decode().strip()
    print(f"  Embedded agent download: {size_str} bytes")

    # Check size — if tiny, the meshinstall URL doesn't work. Use plain agent + MSH instead.
    stdin, stdout, stderr = pv1.exec_command('pct exec 112 -- stat -c %s /tmp/meshagent_win64.exe 2>/dev/null', timeout=5)
    file_size = int(stdout.read().decode().strip() or "0")

    if file_size < 100000:
        print(f"  Embedded agent too small ({file_size}b). Using plain agent + MSH file.")
        # Get plain agent
        stdin, stdout, stderr = pv1.exec_command('pct exec 112 -- curl -sk "https://localhost/meshagents?id=4" -o /tmp/meshagent_win64.exe -w "%{size_download}"', timeout=30)
        print(f"  Plain agent: {stdout.read().decode().strip()} bytes")

        # Get server hash
        stdin, stdout, stderr = pv1.exec_command('pct exec 112 -- openssl x509 -in /opt/meshcentral/meshcentral-data/webserver-cert-public.crt -fingerprint -sha384 -noout', timeout=5)
        hash_out = stdout.read().decode().strip()
        import re
        hash_match = re.search(r'=([A-Fa-f0-9:]+)', hash_out)
        server_hash = hash_match.group(1).replace(":", "").upper() if hash_match else ""
        print(f"  Server hash: {server_hash[:40]}...")

        # Write MSH to CT112
        msh = f"MeshName=WinHunt MeshCentral\nMeshType=2\nMeshID=0x{MESH_ID}\nServerID={server_hash}\nMeshServer=wss://{MESH_IP}:443/agent.ashx\n"
        stdin, stdout, stderr = pv1.exec_command('pct exec 112 -- tee /tmp/meshagent.msh > /dev/null', timeout=5)
        stdin.write(msh)
        stdin.channel.shutdown_write()
        stdout.read()
        use_separate_msh = True
    else:
        use_separate_msh = False

    pv1.close()

    # Download on Windows from CT112
    win_run(f"""
$ProgressPreference = "SilentlyContinue"
$wc = New-Object System.Net.WebClient
Write-Output "Downloading agent from http://{MESH_IP}:8888..."
$wc.DownloadFile("http://{MESH_IP}:8888/meshagent_win64.exe", "$env:TEMP\\meshagent.exe")
Write-Output "Agent: $((Get-Item "$env:TEMP\\meshagent.exe").Length) bytes"
    """, "Download MeshAgent via HTTP")

    if use_separate_msh:
        win_run(f"""
$ProgressPreference = "SilentlyContinue"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile("http://{MESH_IP}:8888/meshagent.msh", "$env:TEMP\\meshagent.msh")
Write-Output "MSH: $((Get-Item "$env:TEMP\\meshagent.msh").Length) bytes"
Get-Content "$env:TEMP\\meshagent.msh"
        """, "Download MSH via HTTP")

    # Install MeshAgent
    if use_separate_msh:
        win_run(r"""
$installDir = "C:\Program Files\Mesh Agent"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item "$env:TEMP\meshagent.exe" "$installDir\MeshAgent.exe" -Force
Copy-Item "$env:TEMP\meshagent.msh" "$installDir\MeshAgent.msh" -Force
Start-Process -FilePath "$installDir\MeshAgent.exe" -ArgumentList "-install" -Wait -NoNewWindow
Start-Sleep -Seconds 8
$svc = Get-Service | Where-Object { $_.Name -like "*mesh*" }
if ($svc) { foreach ($s in $svc) { Write-Output "Service: $($s.Name) = $($s.Status)" } }
else { Write-Output "NO MESH SERVICE" }
        """, "Install MeshAgent")
    else:
        win_run(r"""
$installDir = "C:\Program Files\Mesh Agent"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item "$env:TEMP\meshagent.exe" "$installDir\MeshAgent.exe" -Force
Start-Process -FilePath "$installDir\MeshAgent.exe" -ArgumentList "-install" -Wait -NoNewWindow
Start-Sleep -Seconds 8
$svc = Get-Service | Where-Object { $_.Name -like "*mesh*" }
if ($svc) { foreach ($s in $svc) { Write-Output "Service: $($s.Name) = $($s.Status)" } }
else { Write-Output "NO MESH SERVICE" }
        """, "Install MeshAgent (embedded)")

    # ================================================================
    # STEP B: Download + install dfi_agent package
    # ================================================================
    print("\n" + "=" * 60)
    print("STEP B: Deploy dfi_agent via HTTP")
    print("=" * 60)

    win_run(f"""
$ProgressPreference = "SilentlyContinue"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile("http://{MESH_IP}:8888/dfi_agent.tar.gz", "$env:TEMP\\dfi_agent.tar.gz")
Write-Output "Tarball: $((Get-Item "$env:TEMP\\dfi_agent.tar.gz").Length) bytes"
cd $env:TEMP
if (Test-Path "$env:TEMP\\dfi_agent") {{ Remove-Item -Recurse -Force "$env:TEMP\\dfi_agent" }}
tar xzf dfi_agent.tar.gz
$files = (Get-ChildItem "$env:TEMP\\dfi_agent" -File -ErrorAction SilentlyContinue).Count
Write-Output "Extracted: $files files"
New-Item -ItemType Directory -Force -Path "C:\\Program Files\\DFI\\agent" | Out-Null
Copy-Item -Recurse -Force "$env:TEMP\\dfi_agent" "C:\\Program Files\\DFI\\agent\\"
$deployed = (Get-ChildItem "C:\\Program Files\\DFI\\agent\\dfi_agent" -Recurse -File).Count
Write-Output "Deployed: $deployed files"
    """, "Download + extract dfi_agent")

    # ================================================================
    # STEP C: Install Npcap
    # ================================================================
    print("\n" + "=" * 60)
    print("STEP C: Install Npcap")
    print("=" * 60)

    out, _ = win_run("""
if (Test-Path "C:\\Program Files\\Npcap\\npcap.sys") { Write-Output "NPCAP_OK" } else { Write-Output "NPCAP_MISSING" }
    """, "Check Npcap")

    if "NPCAP_MISSING" in out:
        win_run(f"""
$ProgressPreference = "SilentlyContinue"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile("http://{MESH_IP}:8888/npcap.exe", "$env:TEMP\\npcap.exe")
Write-Output "Npcap: $((Get-Item "$env:TEMP\\npcap.exe").Length) bytes"
Start-Process -FilePath "$env:TEMP\\npcap.exe" -ArgumentList "/S","/winpcap_mode=yes","/loopback_support=yes" -Wait
Start-Sleep -Seconds 5
if (Test-Path "C:\\Program Files\\Npcap\\npcap.sys") {{ Write-Output "NPCAP_INSTALLED" }}
else {{ Write-Output "NPCAP_FAILED" }}
        """, "Install Npcap via HTTP", timeout=180)

    # ================================================================
    # STEP D: Config, audit, service
    # ================================================================
    print("\n" + "=" * 60)
    print("STEP D: Config + audit + service")
    print("=" * 60)

    config = {
        "vm_id": "WINHUNT-TEST", "mgmt_nic_ip": "172.16.3.160", "agent_port": 9200,
        "token": "", "buffer_path": r"C:\Program Files\DFI\data\agent_buffer.db",
        "log_dir": r"C:\Program Files\DFI\logs", "log_level": "INFO", "retention_days": 7,
        "pcap": {
            "enabled": True, "interface": "Ethernet0", "snap_len": 256, "buffer_mb": 16,
            "bpf_filter": "", "flow_timeout_s": 120, "flow_drain_rst_s": 2, "flow_drain_fin_s": 5,
            "max_active_flows": 50000, "max_event_pkts": 128, "max_flow_pkts": 10000,
            "capture_source": 1, "local_networks": ["172.16.3.0/24", "192.168.0.0/24"]
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
    cj = json.dumps(config, indent=2)

    win_run(f"""
@'
{cj}
'@ | Set-Content -Path 'C:\\Program Files\\DFI\\config.json' -Encoding UTF8
$ch = (Get-Content 'C:\\Program Files\\DFI\\config.json' | ConvertFrom-Json).evidence.channels.Count
Write-Output "Config: $ch channels"
    """, "Write config.json")

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

    win_run(r"""
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
$svcName = "WinHuntAgent"
$existing = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($existing) {
    nssm stop $svcName 2>$null
    nssm remove $svcName confirm 2>$null
    Start-Sleep 2
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
Start-Sleep 5
$svc = Get-Service -Name $svcName
Write-Output "Service: $svcName = $($svc.Status)"
    """, "Create + start WinHunt service")

    # ================================================================
    # VERIFICATION
    # ================================================================
    print("\n" + "=" * 60)
    print("VERIFICATION")
    print("=" * 60)

    win_run(r"""
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
Write-Output "=== Python ===" ; python --version
Write-Output "=== Npcap ===" ; if (Test-Path "C:\Program Files\Npcap\npcap.sys") { "OK" } else { "MISSING" }
Write-Output "=== NSSM ===" ; if (Test-Path "C:\Windows\System32\nssm.exe") { "OK" } else { "MISSING" }
Write-Output "=== MeshAgent ==="
Get-Service | Where-Object { $_.Name -like "*mesh*" } | ForEach-Object { "$($_.Name) = $($_.Status)" }
Write-Output "=== DFI Agent ==="
(Get-ChildItem "C:\Program Files\DFI\agent\dfi_agent" -File -ErrorAction SilentlyContinue).Name | Sort-Object
Write-Output "=== Config ==="
$c = Get-Content "C:\Program Files\DFI\config.json" -ErrorAction SilentlyContinue | ConvertFrom-Json
if ($c) { "vm_id=$($c.vm_id) channels=$($c.evidence.channels.Count) nic=$($c.pcap.interface)" }
Write-Output "=== WinHunt Service ==="
Get-Service WinHuntAgent -ErrorAction SilentlyContinue | Format-Table Name, Status, StartType -AutoSize
Write-Output "=== Logs (last 15 lines) ==="
if (Test-Path "C:\Program Files\DFI\logs\service_stderr.log") {
    Get-Content "C:\Program Files\DFI\logs\service_stderr.log" -Tail 15
} elseif (Test-Path "C:\Program Files\DFI\logs\agent.log") {
    Get-Content "C:\Program Files\DFI\logs\agent.log" -Tail 15
} else { "No logs yet" }
    """, "Final check")

    # Check MeshCentral for device
    pv1 = paramiko.SSHClient()
    pv1.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pv1.connect(PV1, username=PV1_USER, password=PV1_PASS, timeout=10)
    meshctrl = "/opt/meshcentral/node_modules/meshcentral/meshctrl.js"
    mbase = f'--url wss://localhost --loginuser admin --loginpass "CHANGE_ME"'
    stdin, stdout, stderr = pv1.exec_command(f'pct exec 112 -- node {meshctrl} {mbase} listdevices --group "WinHunt-Test" 2>&1', timeout=30)
    mc_out = stdout.read().decode().strip()
    print(f"\n[MeshCentral devices]\n  {mc_out}")

    # Cleanup HTTP server
    pv1.exec_command('pct exec 112 -- bash -c "pkill -f http.server 2>/dev/null"', timeout=5)
    pv1.close()

    print("\n" + "=" * 60)
    print("DEPLOYMENT COMPLETE")
    print(f"  MeshCentral: https://{MESH_IP} (admin/CHANGE_ME)")
    print("  WinHunt agent: 172.16.3.160 (WinHuntAgent service)")
    print("=" * 60)


if __name__ == "__main__":
    main()
