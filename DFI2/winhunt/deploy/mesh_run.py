#!/usr/bin/env python3
"""Run PowerShell on Windows 172.16.3.160 via MeshCentral (--reply flag).

Usage:
    python mesh_run.py --status          # built-in WinHunt status check
    python mesh_run.py 'Get-Date'        # run arbitrary PS command
    echo 'Get-Date' | python mesh_run.py # pipe PS from stdin
"""
import paramiko
import sys

PV1 = "192.168.0.100"
NODE_ID = "node//rJxuIjVnZfALO8tHSCnolfbv3suKO0GhuhTBwHJJ170YIsgNVyRb2yfjwrgpWjvn"


def get_pv1():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(PV1, username="root", password="CHANGE_ME", timeout=10)
    return c


def mesh_ps(c, ps_cmd, label="", timeout=30):
    """Execute PowerShell on Windows via MeshCentral, return output."""
    if label:
        print(f"\n{'='*50}")
        print(label)
        print('='*50)

    # Write a bash script on CT112 to avoid escaping hell
    script = f"""#!/bin/bash
cd /opt/meshcentral
node node_modules/meshcentral/meshctrl.js runcommand \\
  --id "{NODE_ID}" \\
  --run '{ps_cmd}' \\
  --powershell --reply \\
  --url wss://localhost \\
  --loginuser admin --loginpass "CHANGE_ME" 2>&1
"""
    stdin, stdout, _ = c.exec_command(
        'pct exec 112 -- tee /tmp/_mc.sh > /dev/null', timeout=10)
    stdin.write(script)
    stdin.channel.shutdown_write()
    stdout.read()

    stdin2, stdout2, stderr2 = c.exec_command(
        'pct exec 112 -- bash /tmp/_mc.sh', timeout=timeout + 30)
    out = stdout2.read().decode().strip()
    err = stderr2.read().decode().strip()
    if out:
        print(out)
    if err:
        print(f"ERR: {err[:300]}")
    return out


def mesh_ps_file(c, ps_script, label="", timeout=60):
    """Execute a multi-line PS script via file transfer + MeshCentral."""
    if label:
        print(f"\n{'='*50}")
        print(label)
        print('='*50)

    # Write PS1 to CT112
    stdin, stdout, _ = c.exec_command(
        'pct exec 112 -- tee /tmp/_mc_script.ps1 > /dev/null', timeout=10)
    stdin.write(ps_script)
    stdin.channel.shutdown_write()
    stdout.read()

    # Ensure HTTP server is running for PS1 download
    stdin2, stdout2, _ = c.exec_command(
        'pct exec 112 -- ss -tlnp | grep 8888', timeout=5)
    if "8888" not in stdout2.read().decode():
        c.exec_command(
            'pct exec 112 -- bash -c "setsid python3 -m http.server 8888 '
            '--directory /tmp </dev/null >/dev/null 2>&1 &"', timeout=5)
        import time; time.sleep(1)

    # meshctrl: download PS1 + execute via -File
    run_script = f"""#!/bin/bash
cd /opt/meshcentral
node node_modules/meshcentral/meshctrl.js runcommand \\
  --id "{NODE_ID}" \\
  --run "powershell -ExecutionPolicy Bypass -Command \\"(New-Object System.Net.WebClient).DownloadFile('"'"'http://172.16.3.112:8888/_mc_script.ps1'"'"','"'"'C:\\TEMP\\_mc_script.ps1'"'"'); & C:\\TEMP\\_mc_script.ps1\\"" \\
  --powershell --reply \\
  --url wss://localhost \\
  --loginuser admin --loginpass "CHANGE_ME" 2>&1
"""
    stdin3, stdout3, _ = c.exec_command(
        'pct exec 112 -- tee /tmp/_mc_file.sh > /dev/null', timeout=10)
    stdin3.write(run_script)
    stdin3.channel.shutdown_write()
    stdout3.read()

    stdin4, stdout4, stderr4 = c.exec_command(
        'pct exec 112 -- bash /tmp/_mc_file.sh', timeout=timeout + 30)
    out = stdout4.read().decode().strip()
    err = stderr4.read().decode().strip()
    if out:
        print(out)
    if err:
        print(f"ERR: {err[:300]}")
    return out


def status_check():
    """Built-in WinHunt full status check."""
    c = get_pv1()

    mesh_ps(c,
        'Get-Service WinHuntAgent,"Mesh Agent" | Format-List Name,Status,StartType',
        "Services")

    mesh_ps(c,
        'Get-Content "C:\\Program Files\\DFI\\logs\\agent.log" -Tail 25',
        "Agent Log (last 25)")

    mesh_ps(c,
        'Get-Content "C:\\DFI\\stderr.log" -Tail 5',
        "stderr (last 5)")

    mesh_ps(c, r"""$files = Get-ChildItem "C:\Program Files\DFI\staging" -ErrorAction SilentlyContinue
$totalKB = [math]::Round(($files | Measure-Object Length -Sum).Sum/1KB, 1)
Write-Output "Files: $($files.Count)  Total: ${totalKB}KB"
$files | Sort-Object LastWriteTime -Descending | Select-Object -First 5 | ForEach-Object { Write-Output "  $($_.Name)  $([math]::Round($_.Length/1KB,1))KB  $($_.LastWriteTime)" }""",
        "Staging Files")

    mesh_ps(c, r"""$db = Get-Item "C:\Program Files\DFI\data\agent_buffer.db" -ErrorAction SilentlyContinue
if ($db) { Write-Output "DB: $([math]::Round($db.Length/1KB,1))KB  Modified: $($db.LastWriteTime)" }
Get-Process python -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "PID=$($_.Id) CPU=$($_.CPU) Mem=$([math]::Round($_.WorkingSet64/1MB,1))MB Start=$($_.StartTime)" }""",
        "DB + Process")

    mesh_ps(c, r"""$cfg = Get-Content "C:\DFI\config.json" -Raw | ConvertFrom-Json
Write-Output "vm_id=$($cfg.vm_id)  iface=$($cfg.pcap.interface)  port=$($cfg.agent_port)"
Write-Output "Time: $(Get-Date)" """,
        "Config + Time")

    c.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--status":
        status_check()
    elif len(sys.argv) > 1:
        c = get_pv1()
        mesh_ps(c, " ".join(sys.argv[1:]))
        c.close()
    else:
        ps = sys.stdin.read().strip()
        if ps:
            c = get_pv1()
            mesh_ps(c, ps)
            c.close()
        else:
            print("Usage: mesh_run.py --status | mesh_run.py 'PS command' | echo 'PS' | mesh_run.py")
