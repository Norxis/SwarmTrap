#!/usr/bin/env python3
"""Check Windows status via fire-and-forget + CT112 HTTP file transfer."""
import paramiko, time, sys

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("192.168.0.100", username="root", password="CHANGE_ME", timeout=10)

NODE = "node//rJxuIjVnZfALO8tHSCnolfbv3suKO0GhuhTBwHJJ170YIsgNVyRb2yfjwrgpWjvn"
MESH_IP = "172.16.3.112"
HTTP_PORT = 8888

# Step 1: Write PS1 script to CT112
ps_script = r"""$out = @()
$out += "TIME: $(Get-Date -Format o)"

$svc = Get-Service WinHuntAgent -ErrorAction SilentlyContinue
$out += "AGENT_SVC: $($svc.Status)"

$ma = Get-Service 'Mesh Agent' -ErrorAction SilentlyContinue
$out += "MESH_SVC: $($ma.Status)"

$py = Get-Process python -ErrorAction SilentlyContinue
if ($py) {
    $out += "PYTHON: PID=$($py.Id) MEM=$([math]::Round($py.WorkingSet64/1MB,1))MB START=$($py.StartTime)"
} else {
    $out += "PYTHON: NOT_RUNNING"
}

$staging = Get-ChildItem "C:\Program Files\DFI\staging" -ErrorAction SilentlyContinue | Measure-Object Length -Sum
$out += "STAGING: $($staging.Count) files $([math]::Round($staging.Sum/1KB,1))KB"

$log = Get-Content "C:\Program Files\DFI\logs\agent.log" -Tail 5 -ErrorAction SilentlyContinue
$out += "LAST_LOG:"
$log | ForEach-Object { $out += "  $_" }

$db = Get-Item "C:\Program Files\DFI\data\agent_buffer.db" -ErrorAction SilentlyContinue
if ($db) { $out += "DB: $([math]::Round($db.Length/1KB,1))KB" }
else { $out += "DB: MISSING" }

$out -join "`n" | Out-File "C:\TEMP\mc_status.txt" -Encoding utf8
"""

print("Step 1: Writing PS1 script to CT112...")
si, so, _ = c.exec_command("pct exec 112 -- tee /tmp/_status.ps1 > /dev/null", timeout=10)
si.write(ps_script)
si.channel.shutdown_write()
so.read()

# Step 2: Ensure HTTP server running on CT112
print("Step 2: Ensuring CT112 HTTP server...")
si, so, _ = c.exec_command("pct exec 112 -- ss -tlnp | grep 8888", timeout=10)
if "8888" not in so.read().decode():
    c.exec_command(
        'pct exec 112 -- bash -c "setsid python3 -m http.server 8888 --directory /tmp </dev/null >/dev/null 2>&1 &"',
        timeout=10)
    time.sleep(2)
    print("  HTTP server started")
else:
    print("  HTTP server already running")

# Step 3: Fire-and-forget: download PS1 + execute
dl_cmd = (
    f"(New-Object System.Net.WebClient).DownloadFile("
    f"'http://{MESH_IP}:{HTTP_PORT}/_status.ps1',"
    f"'C:\\TEMP\\_status.ps1'); "
    f"& C:\\TEMP\\_status.ps1"
)

# Write meshctrl script
mc_script = f"""#!/bin/bash
cd /opt/meshcentral
node node_modules/meshcentral/meshctrl.js runcommand \\
  --id "{NODE}" \\
  --run "powershell -ExecutionPolicy Bypass -Command \\"{dl_cmd}\\"" \\
  --url wss://localhost \\
  --loginuser admin --loginpass "CHANGE_ME" 2>&1
"""

si, so, _ = c.exec_command("pct exec 112 -- tee /tmp/_mc.sh > /dev/null", timeout=10)
si.write(mc_script)
si.channel.shutdown_write()
so.read()

print("Step 3: Sending fire-and-forget command...")
si, so, se = c.exec_command("pct exec 112 -- bash /tmp/_mc.sh", timeout=30)
result = so.read().decode().strip()
print(f"  meshctrl: {result}")

# Step 4: Wait and then retrieve result
print("Step 4: Waiting 15s for Windows to execute...")
time.sleep(15)

# Try to get the file back: have Windows push mc_status.txt to CT112
push_cmd = (
    f"(New-Object System.Net.WebClient).UploadFile("
    f"'http://{MESH_IP}:{HTTP_PORT}/mc_status.txt',"
    f"'C:\\TEMP\\mc_status.txt')"
)
# Actually HTTP server doesn't accept uploads. Instead, use meshctrl runcommand
# to cat the file content back via --reply... but --reply is broken.

# Alternative: have Windows serve the file and CT112 downloads it.
# Or: cat the file and POST it to a nc listener.

# Simplest: Start nc listener, have Windows POST content to it
print("Step 5: Starting nc listener on CT112:9999...")
c.exec_command("pct exec 112 -- bash -c 'rm -f /tmp/mc_result.raw'", timeout=5)
c.exec_command(
    'pct exec 112 -- bash -c "timeout 30 nc -l -p 9999 > /tmp/mc_result.raw 2>&1 &"',
    timeout=5)
time.sleep(1)

# Fire-and-forget: read status file and POST to CT112
post_cmd = (
    f"$body = Get-Content C:\\TEMP\\mc_status.txt -Raw; "
    f"Invoke-WebRequest -Uri 'http://{MESH_IP}:9999/' -Method POST -Body $body"
)
mc_post = f"""#!/bin/bash
cd /opt/meshcentral
node node_modules/meshcentral/meshctrl.js runcommand \\
  --id "{NODE}" \\
  --run '{post_cmd}' \\
  --powershell \\
  --url wss://localhost \\
  --loginuser admin --loginpass "CHANGE_ME" 2>&1
"""
si, so, _ = c.exec_command("pct exec 112 -- tee /tmp/_mc.sh > /dev/null", timeout=10)
si.write(mc_post)
si.channel.shutdown_write()
so.read()

print("Step 5b: Sending POST-back command...")
si, so, se = c.exec_command("pct exec 112 -- bash /tmp/_mc.sh", timeout=30)
print(f"  meshctrl: {so.read().decode().strip()}")

print("Step 6: Waiting 15s for POST...")
time.sleep(15)

# Read captured POST
si, so, se = c.exec_command("pct exec 112 -- cat /tmp/mc_result.raw", timeout=10)
raw = so.read().decode().strip()
if raw:
    print(f"\n{'='*50}")
    print("WINDOWS STATUS")
    print(f"{'='*50}")
    # Parse POST body (skip HTTP headers)
    parts = raw.split("\r\n\r\n", 1)
    body = parts[1] if len(parts) > 1 else raw
    print(body)
else:
    print("  No POST received. nc captured nothing.")
    si, so, _ = c.exec_command("pct exec 112 -- ls -la /tmp/mc_result.raw", timeout=5)
    print(f"  {so.read().decode().strip()}")

c.close()
