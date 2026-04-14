#!/usr/bin/env python3
"""Stage 3: Deploy dfi_agent package to SRV25 via WinRM."""
import base64
import winrm
import json
import sys

HOST = "http://172.16.3.160:5985/wsman"
USER = "Administrator"
PASS = "CHANGE_ME"

def run_ps(script: str, label: str = "") -> tuple[str, str, int]:
    s = winrm.Session(HOST, auth=(USER, PASS), transport="ntlm")
    r = s.run_ps(script)
    out = r.std_out.decode("utf-8", errors="replace")
    # Filter out CLIXML progress noise
    err_raw = r.std_err.decode("utf-8", errors="replace")
    err = ""
    for line in err_raw.split("\n"):
        if "<Obj" not in line and "CLIXML" not in line and "progress" not in line.lower():
            err += line + "\n"
    err = err.strip()
    if label:
        print(f"[{label}] exit={r.status_code}")
    if out.strip():
        for line in out.strip().split("\n")[-15:]:
            print(f"  {line}")
    if err and r.status_code != 0:
        print(f"  ERR: {err[:300]}")
    return out, err, r.status_code

def main():
    # Step 1: Create directory structure
    print("=" * 50)
    print("STEP 1: Create DFI directories")
    print("=" * 50)
    run_ps("""
        $dirs = @(
            'C:\\Program Files\\DFI\\agent',
            'C:\\Program Files\\DFI\\data',
            'C:\\Program Files\\DFI\\logs',
            'C:\\Program Files\\DFI\\staging'
        )
        foreach ($d in $dirs) {
            New-Item -ItemType Directory -Force -Path $d | Out-Null
            Write-Output "Created: $d"
        }
    """, "mkdir")

    # Step 2: Transfer agent code via base64 tarball
    print("\n" + "=" * 50)
    print("STEP 2: Transfer dfi_agent package")
    print("=" * 50)
    with open("/tmp/dfi_agent_b64.txt", "r") as f:
        b64_data = f.read()

    # Send in chunks (WinRM has message size limits)
    chunk_size = 30000
    chunks = [b64_data[i:i+chunk_size] for i in range(0, len(b64_data), chunk_size)]
    print(f"  Sending {len(b64_data)} chars in {len(chunks)} chunks...")

    # Write chunks to temp file on remote
    for i, chunk in enumerate(chunks):
        mode = "Set" if i == 0 else "Add"
        # Escape for PowerShell
        run_ps(f"""
            ${mode}-Content -Path "$env:TEMP\\dfi_agent_b64.txt" -Value '{chunk}' -NoNewline
        """, f"chunk {i+1}/{len(chunks)}")

    # Decode and extract
    run_ps("""
        $b64 = Get-Content "$env:TEMP\\dfi_agent_b64.txt" -Raw
        $bytes = [System.Convert]::FromBase64String($b64)
        [System.IO.File]::WriteAllBytes("$env:TEMP\\dfi_agent.tar.gz", $bytes)
        Write-Output "Wrote $($bytes.Length) bytes to dfi_agent.tar.gz"
    """, "decode")

    # Extract using tar (available in Win Server 2025)
    run_ps(r"""
        cd "$env:TEMP"
        tar xzf dfi_agent.tar.gz
        if (Test-Path "$env:TEMP\dfi_agent") {
            Copy-Item -Recurse -Force "$env:TEMP\dfi_agent" "C:\Program Files\DFI\agent\"
            $count = (Get-ChildItem "C:\Program Files\DFI\agent\dfi_agent" -Recurse -File).Count
            Write-Output "Deployed $count files to C:\Program Files\DFI\agent\dfi_agent\"
        } else {
            Write-Error "dfi_agent directory not found after extraction"
        }
    """, "extract")

    # Step 3: Install pip dependencies
    print("\n" + "=" * 50)
    print("STEP 3: Install pip dependencies")
    print("=" * 50)
    run_ps(r"""
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        & python -m pip install pcapy-ng pywin32 2>&1 | Select-Object -Last 5
        Write-Output "pip install complete"
    """, "pip")

    # Step 4: Configure audit policies
    print("\n" + "=" * 50)
    print("STEP 4: Configure Windows audit policies")
    print("=" * 50)
    run_ps(r"""
        # Enable advanced audit policies
        auditpol /set /subcategory:"Logon" /success:enable /failure:enable
        auditpol /set /subcategory:"Logoff" /success:enable
        auditpol /set /subcategory:"Special Logon" /success:enable
        auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
        auditpol /set /subcategory:"Process Creation" /success:enable
        auditpol /set /subcategory:"Process Termination" /success:enable
        auditpol /set /subcategory:"Security System Extension" /success:enable
        auditpol /set /subcategory:"File System" /success:enable /failure:enable
        auditpol /set /subcategory:"Registry" /success:enable
        auditpol /set /subcategory:"Handle Manipulation" /success:enable
        auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
        auditpol /set /subcategory:"Security Group Management" /success:enable

        # Enable command line in process creation events
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

        # Expand event log sizes
        wevtutil sl Security /ms:134217728
        wevtutil sl System /ms:67108864
        wevtutil sl Application /ms:67108864
        wevtutil sl "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" /ms:33554432
        wevtutil sl "Microsoft-Windows-Windows Defender/Operational" /ms:67108864
        wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:67108864

        Write-Output "Audit policies configured"
    """, "audit")

    # Step 5: Generate config.json
    print("\n" + "=" * 50)
    print("STEP 5: Generate config.json")
    print("=" * 50)
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
            "enabled": True,
            "interface": "Ethernet0",
            "snap_len": 256,
            "buffer_mb": 16,
            "bpf_filter": "",
            "flow_timeout_s": 120,
            "flow_drain_rst_s": 2,
            "flow_drain_fin_s": 5,
            "max_active_flows": 50000,
            "max_event_pkts": 128,
            "max_flow_pkts": 10000,
            "capture_source": 1,
            "local_networks": ["172.16.3.0/24", "192.168.0.0/24"]
        },
        "evidence": {
            "enabled": True,
            "channels": [
                "Security",
                "System",
                "Application",
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
            "suspicious_patterns": [
                r"(cmd|powershell|pwsh).*(/c|/k|-enc|-e\s)",
                r"(nc|ncat|netcat)\s.*(-e|-c)",
                r"(wget|curl|invoke-webrequest|iwr)\s",
                r"(certutil)\s.*(-urlcache|-decode)",
                r"(bitsadmin)\s.*/transfer"
            ],
            "download_patterns": [
                r"(certutil)\s.*-urlcache",
                r"(bitsadmin)\s.*/transfer",
                r"(wget|curl|invoke-webrequest|iwr)\s+https?://"
            ]
        },
        "exporter": {
            "enabled": True,
            "staging_dir": r"C:\Program Files\DFI\staging",
            "export_interval_s": 30,
            "max_rows_per_file": 10000,
            "file_prefix": "dfi",
            "retention_hours": 24
        },
        "services": [
            {"name": "rdp", "ports": [3389], "enabled": True},
            {"name": "smb", "ports": [445], "enabled": True},
            {"name": "winrm", "ports": [5985, 5986], "enabled": True}
        ]
    }
    config_json = json.dumps(config, indent=2)
    # Escape for PowerShell single-quoted string
    config_json_escaped = config_json.replace("'", "''")

    run_ps(f"""
        $cfg = @'
{config_json}
'@
        Set-Content -Path 'C:\\Program Files\\DFI\\config.json' -Value $cfg -Encoding UTF8
        Write-Output "Config written to C:\\Program Files\\DFI\\config.json"
        Write-Output "Channels: $((Get-Content 'C:\\Program Files\\DFI\\config.json' | ConvertFrom-Json).evidence.channels.Count)"
    """, "config")

    # Step 6: Create Windows service via NSSM
    print("\n" + "=" * 50)
    print("STEP 6: Create Windows service")
    print("=" * 50)
    run_ps(r"""
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

        $svcName = "WinHuntAgent"
        # Remove existing if present
        $existing = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($existing) {
            nssm stop $svcName 2>$null
            nssm remove $svcName confirm 2>$null
            Start-Sleep -Seconds 2
        }

        $pythonPath = (Get-Command python).Source
        nssm install $svcName $pythonPath "-m" "dfi_agent" "--config" "C:\Program Files\DFI\config.json"
        nssm set $svcName AppDirectory "C:\Program Files\DFI\agent"
        nssm set $svcName DisplayName "WinHunt DFI Agent"
        nssm set $svcName Description "DFI Windows capture agent - Npcap + ETW evidence collector"
        nssm set $svcName Start SERVICE_AUTO_START
        nssm set $svcName AppStdout "C:\Program Files\DFI\logs\service_stdout.log"
        nssm set $svcName AppStderr "C:\Program Files\DFI\logs\service_stderr.log"
        nssm set $svcName AppRotateFiles 1
        nssm set $svcName AppRotateBytes 10485760

        nssm start $svcName
        Start-Sleep -Seconds 5
        $svc = Get-Service -Name $svcName
        Write-Output "Service $svcName status: $($svc.Status)"
    """, "service")

    # Step 7: Final verification
    print("\n" + "=" * 50)
    print("STEP 7: Final verification")
    print("=" * 50)
    run_ps(r"""
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

        Write-Output "=== Python ==="
        python --version

        Write-Output "`n=== Npcap ==="
        if (Test-Path "C:\Program Files\Npcap\npcap.sys") { Write-Output "OK" } else { Write-Output "MISSING" }

        Write-Output "`n=== DFI Agent Files ==="
        (Get-ChildItem "C:\Program Files\DFI\agent\dfi_agent" -File).Name | Sort-Object

        Write-Output "`n=== Config ==="
        $cfg = Get-Content "C:\Program Files\DFI\config.json" | ConvertFrom-Json
        Write-Output "vm_id: $($cfg.vm_id)"
        Write-Output "channels: $($cfg.evidence.channels.Count)"
        Write-Output "interface: $($cfg.pcap.interface)"

        Write-Output "`n=== Service ==="
        Get-Service WinHuntAgent | Format-List Name, Status, StartType

        Write-Output "`n=== Logs (last 10 lines) ==="
        if (Test-Path "C:\Program Files\DFI\logs\agent.log") {
            Get-Content "C:\Program Files\DFI\logs\agent.log" -Tail 10
        } else {
            Write-Output "No agent.log yet"
        }
        if (Test-Path "C:\Program Files\DFI\logs\service_stderr.log") {
            Write-Output "`n=== Service stderr ==="
            Get-Content "C:\Program Files\DFI\logs\service_stderr.log" -Tail 10
        }
    """, "verify")

    print("\n=== Agent deployment complete ===")

if __name__ == "__main__":
    main()
