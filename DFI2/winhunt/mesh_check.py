import winrm
import paramiko
import sys
import json

def section(title):
    print("\n" + "=" * 60)
    print("  " + title)
    print("=" * 60 + "\n")

# ── Step 1 & 2: Connect to Windows 172.16.3.160 via WinRM ──
section("STEP 1 & 2: WinRM to 172.16.3.160 -- Restart MeshAgent & Check Status")

ps_script = r'''
# Restart MeshAgent service
Restart-Service "Mesh Agent" -Force
Start-Sleep 5

# Check service status
Get-Service | Where-Object { $_.Name -like "*mesh*" } | Format-Table Name, Status -AutoSize

# Check the MSH file contents
if (Test-Path "C:\Program Files\Mesh Agent\MeshAgent.msh") {
    Write-Output "`n=== MSH File ==="
    Get-Content "C:\Program Files\Mesh Agent\MeshAgent.msh"
}

# Check outbound connections to 172.16.3.112
Start-Sleep 10
Write-Output "`n=== Connections to 172.16.3.112 ==="
Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq "172.16.3.112" } | Format-Table LocalPort, RemotePort, State -AutoSize

# Check MeshAgent log if it exists
$logDir = "C:\Program Files\Mesh Agent"
Get-ChildItem $logDir -Filter "*.log" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Output "`n=== $($_.Name) ==="
    Get-Content $_.FullName -Tail 20 -ErrorAction SilentlyContinue
}
'''

try:
    session = winrm.Session(
        'http://172.16.3.160:5985/wsman',
        auth=('Administrator', 'CHANGE_ME'),
        transport='ntlm',
        read_timeout_sec=90,
        operation_timeout_sec=60
    )
    result = session.run_ps(ps_script)

    stdout = result.std_out.decode('utf-8', errors='replace').strip()
    stderr = result.std_err.decode('utf-8', errors='replace').strip()

    if stdout:
        print("[STDOUT]")
        print(stdout)
    if stderr:
        print("\n[STDERR]")
        print(stderr)
    print("\n[Return code: {}]".format(result.status_code))
except Exception as e:
    print("[ERROR] WinRM connection failed: {}".format(e))

# ── Step 3: Connect to PV1 via Paramiko and check MeshCentral ──
section("STEP 3: Paramiko to PV1 (192.168.0.100) -- Check MeshCentral devices & logs")

def ssh_run(client, cmd, label):
    print("--- {} ---".format(label))
    stdin, stdout, stderr = client.exec_command(cmd, timeout=60)
    out = stdout.read().decode('utf-8', errors='replace').strip()
    err = stderr.read().decode('utf-8', errors='replace').strip()
    if out:
        print(out)
    if err:
        print("[stderr] {}".format(err))
    print()

try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect('192.168.0.100', port=22, username='root', password='CHANGE_ME', timeout=15)

    # List devices
    ssh_run(ssh,
        'pct exec 112 -- node /opt/meshcentral/node_modules/meshcentral/meshctrl.js '
        '--url wss://localhost --loginuser admin --loginpass "CHANGE_ME" listdevices --json 2>&1',
        "MeshCentral listdevices"
    )

    # Recent MeshCentral logs
    ssh_run(ssh,
        "pct exec 112 -- bash -c 'journalctl -u meshcentral --no-pager -n 20 | grep -i -E \"agent|connect|172.16.3\" || echo \"(no matching log lines)\"'",
        "MeshCentral recent logs (agent/connect/172.16.3)"
    )

    ssh.close()
except Exception as e:
    print("[ERROR] Paramiko connection failed: {}".format(e))

print("\n--- Done ---")
