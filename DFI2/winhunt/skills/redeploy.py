#!/usr/bin/env python3
"""Redeploy dfi_agent code + config to Windows via MeshCentral.

Usage: python skills/redeploy.py
"""
import sys, os, io, tarfile, json, time
sys.path.insert(0, os.path.dirname(__file__))
from mesh import MeshSession

WINHUNT_DIR = "/home/colo8gent/DFI2/winhunt"
MESH_IP = "172.16.3.112"


def main():
    # 1. Package agent tarball
    agent_dir = os.path.join(WINHUNT_DIR, "dfi_agent")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(agent_dir, arcname="dfi_agent")
    tarball = buf.getvalue()
    local_tar = "/tmp/dfi_agent.tar.gz"
    with open(local_tar, "wb") as f:
        f.write(tarball)
    print(f"Tarball: {len(tarball)} bytes")

    # 2. Build config — use forward slashes in JSON (Windows Python handles them)
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
                "Microsoft-Windows-WMI-Activity/Operational",
                "Microsoft-Windows-DNS-Client/Operational"
            ]
        },
        "exporter": {
            "staging_dir": r"C:\Program Files\DFI\staging",
            "export_interval_s": 30,
            "max_rows_per_file": 10000,
            "retention_hours": 24,
            "clickhouse_url": "http://172.16.3.2:8123",
            "clickhouse_db": "dfi"
        },
        "eyes": {
            "process_monitor": True,
            "process_monitor_interval_s": 5,
            "socket_monitor": True,
            "socket_monitor_interval_s": 10,
            "dns_monitor": True,
            "file_integrity": True,
            "file_integrity_interval_s": 60,
            "shell_profiler": True,
            "honeypot_detection": True,
            "breadcrumb_tracking": True,
            "memory_forensics": True
        },
        "hand": {
            "enabled": True,
            "max_queue_size": 256,
            "default_timeout": 30
        },
        "comm": {
            "heartbeat_interval_s": 60,
            "batch_idle_s": 30,
            "batch_active_s": 5,
            "priority_immediate": True
        },
        "inference": {
            "xgboost_enabled": True,
            "model_path": r"C:\Program Files\DFI\models\xgb_model.json"
        },
        "standalone": {
            "labeler_enabled": True,
            "alert_enabled": True,
            "alert_threshold": 0.85
        },
        "services": {
            "rdp": {"ports": [3389], "enabled": True},
            "smb": {"ports": [445], "enabled": True},
            "winrm": {"ports": [5985, 5986], "enabled": True},
            "mssql": {"ports": [1433], "enabled": True}
        }
    }
    config_json = json.dumps(config, indent=2)
    config_path = "/tmp/dfi_config.json"
    with open(config_path, "w") as f:
        f.write(config_json)

    with MeshSession() as m:
        # 3. Upload tarball + config to CT112
        print("\nUploading to CT112...")
        sftp = m._conn.open_sftp()
        sftp.put(local_tar, "/tmp/dfi_agent.tar.gz")
        sftp.put(config_path, "/tmp/dfi_config.json")
        sftp.close()
        m._pv1("pct push 112 /tmp/dfi_agent.tar.gz /tmp/dfi_agent.tar.gz")
        m._pv1("pct push 112 /tmp/dfi_config.json /tmp/dfi_config.json")
        m._ensure_http()
        print("Files staged on CT112")

        # 4. Enable DNS Client event log (required for dns_monitor eye sensor)
        m.ps('wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true 2>$null; Write-Output "DNS Client log enabled"',
             "Enable DNS Log")

        # 4b. Ensure firewall rule for agent API port 9200
        m.ps('New-NetFirewallRule -DisplayName "DFI Agent API" -Direction Inbound -LocalPort 9200 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue; Write-Output "Firewall rule OK"',
             "Firewall Rule")

        # 5. Stop agent, deploy, restart
        m.ps('nssm stop WinHuntAgent 2>$null; Start-Sleep 2; Write-Output "Stopped"',
             "Stop Agent")

        # Step A: Clean old data + create dirs
        m.ps(r"""$ProgressPreference = "SilentlyContinue"
Remove-Item "C:\Program Files\DFI\data\agent_buffer.db*" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\DFI\stderr.log" -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "C:\TEMP" | Out-Null
New-Item -ItemType Directory -Force -Path "C:\Program Files\DFI\models" | Out-Null
New-Item -ItemType Directory -Force -Path "C:\Program Files\DFI\dataset" | Out-Null
Write-Output "Dirs ready" """, "Prep Dirs", timeout=15)

        # Step B: Download tarball
        dl_tarball = r"""$ProgressPreference = "SilentlyContinue"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile("http://__MESH_IP__:8888/dfi_agent.tar.gz", "C:\TEMP\dfi_agent.tar.gz")
$size = (Get-Item "C:\TEMP\dfi_agent.tar.gz").Length
Write-Output "Tarball: $size bytes" """.replace("__MESH_IP__", MESH_IP)
        m.ps(dl_tarball, "Download Tarball", timeout=30)

        # Step C: Extract + download config
        extract_cmd = r"""python -c "import tarfile,shutil,os; shutil.rmtree(r'C:\Program Files\DFI\agent\dfi_agent', True); os.makedirs(r'C:\Program Files\DFI\agent', exist_ok=True); t=tarfile.open(r'C:\TEMP\dfi_agent.tar.gz'); t.extractall(r'C:\Program Files\DFI\agent'); t.close(); print('extracted')"
$ProgressPreference = "SilentlyContinue"
(New-Object System.Net.WebClient).DownloadFile("http://__MESH_IP__:8888/dfi_config.json", "C:\DFI\config.json")
Write-Output "Config deployed" """.replace("__MESH_IP__", MESH_IP)
        m.ps(extract_cmd, "Extract + Config", timeout=60)

        # Step D: Verify file count
        m.ps(r"""$files = (Get-ChildItem "C:\Program Files\DFI\agent\dfi_agent" -Filter *.py -Recurse -ErrorAction SilentlyContinue).Count
Write-Output "Agent files: $files"
$dirs = (Get-ChildItem "C:\Program Files\DFI\agent\dfi_agent" -Directory -ErrorAction SilentlyContinue).Name -join ", "
Write-Output "Subdirs: $dirs" """, "Verify Deploy", timeout=15)

        m.ps(r"""nssm start WinHuntAgent
Start-Sleep 15
$svc = Get-Service WinHuntAgent
Write-Output "Service: $($svc.Status)"
Write-Output "`n=== agent.log (last 25 lines) ==="
Get-Content "C:\Program Files\DFI\logs\agent.log" -Tail 25 -ErrorAction SilentlyContinue
Write-Output "`n=== stderr ==="
Get-Content "C:\DFI\stderr.log" -Tail 10 -ErrorAction SilentlyContinue""",
             "Start + Verify", timeout=45)

        # Cleanup HTTP server
        m._ct('bash -c "pkill -f \'http.server 8888\' 2>/dev/null; true"')

    print("\n" + "=" * 50)
    print("DONE")
    print("=" * 50)


if __name__ == "__main__":
    main()
