#!/usr/bin/env python3
"""Use fire-and-forget to check agent state and write status to a shared location.
Then retrieve via the CT112 HTTP file server approach."""
import paramiko, time

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("192.168.0.100", username="root", password="CHANGE_ME", timeout=10)

NODE = "node//rJxuIjVnZfALO8tHSCnolfbv3suKO0GhuhTBwHJJ170YIsgNVyRb2yfjwrgpWjvn"
MESH_IP = "172.16.3.112"

def faf(ps_cmd, label=""):
    """Fire-and-forget PS command via meshctrl."""
    script = f"""#!/bin/bash
cd /opt/meshcentral
node node_modules/meshcentral/meshctrl.js runcommand \\
  --id "{NODE}" \\
  --run "{ps_cmd}" \\
  --powershell \\
  --url wss://localhost \\
  --loginuser admin --loginpass "CHANGE_ME" 2>&1
"""
    si, so, _ = c.exec_command("pct exec 112 -- tee /tmp/_mc.sh > /dev/null", timeout=10)
    si.write(script)
    si.channel.shutdown_write()
    so.read()
    si, so, se = c.exec_command("pct exec 112 -- bash /tmp/_mc.sh", timeout=30)
    out = so.read().decode().strip()
    if label:
        print(f"  [{label}] {out}")
    return out


# Step 1: Write comprehensive status to C:\TEMP\mc_status.txt
# Then push it to CT112 via HTTP POST or have Windows write to a UNC share
# Simpler: have Windows push to CT112 HTTP

# Actually, let's use the approach of having Windows upload to CT112 via HTTP
# We need a way to get the output back. Since download doesn't work,
# let's use the CT112 HTTP server and have Windows POST results back.

# Even simpler: use fire-and-forget to write to file,
# then use fire-and-forget again to make Windows serve/send that file.
# Or: have Windows write to a well-known path and use meshctrl runcommand
# to cat the file and redirect via network.

# Actually the simplest approach: have Windows send output via HTTP POST to CT112
print("Step 1: Start HTTP listener on CT112...")
# Use nc to listen for POST
listener = """#!/bin/bash
timeout 20 nc -l -p 9999 > /tmp/mc_result.txt 2>&1 &
echo "Listener started"
"""
si, so, _ = c.exec_command("pct exec 112 -- tee /tmp/_listen.sh > /dev/null", timeout=10)
si.write(listener)
si.channel.shutdown_write()
so.read()
si, so, se = c.exec_command("pct exec 112 -- bash /tmp/_listen.sh", timeout=10)
print(f"  Listener: {so.read().decode().strip()}")
time.sleep(1)

# Step 2: Fire-and-forget - make Windows POST status to CT112:9999
ps_cmd = (
    "$status = @(); "
    "$status += 'TIME: ' + (Get-Date -Format o); "
    "$svc = Get-Service WinHuntAgent -EA SilentlyContinue; "
    "$status += 'AGENT: ' + $svc.Status; "
    "$ma = Get-Service 'Mesh Agent' -EA SilentlyContinue; "
    "$status += 'MESH: ' + $ma.Status; "
    "$py = Get-Process python -EA SilentlyContinue; "
    "if ($py) { $status += 'PYTHON: PID=' + $py.Id + ' MEM=' + [math]::Round($py.WorkingSet64/1MB,1) + 'MB' } "
    "else { $status += 'PYTHON: NOT RUNNING' }; "
    "$staging = (Get-ChildItem 'C:\\Program Files\\DFI\\staging' -EA SilentlyContinue | Measure-Object Length -Sum); "
    "$status += 'STAGING: ' + $staging.Count + ' files ' + [math]::Round($staging.Sum/1KB,1) + 'KB'; "
    "$log = Get-Content 'C:\\Program Files\\DFI\\logs\\agent.log' -Tail 3 -EA SilentlyContinue; "
    "$status += 'LOG:'; "
    "$log | ForEach-Object { $status += '  ' + $_ }; "
    "$body = ($status -join \"`n\"); "
    f"try {{ (New-Object System.Net.WebClient).UploadString('http://{MESH_IP}:9999/', $body) }} "
    "catch { $body | Out-File C:\\TEMP\\mc_status.txt -Encoding utf8 }"
)

print("Step 2: Fire-and-forget status command...")
faf(ps_cmd, "status")

# Wait for Windows to execute and POST back
print("Step 3: Waiting 10s for response...")
time.sleep(10)

# Read result from nc capture
si, so, se = c.exec_command("pct exec 112 -- cat /tmp/mc_result.txt", timeout=10)
result = so.read().decode().strip()
if result:
    print(f"\n{'='*50}")
    print("STATUS FROM WINDOWS")
    print(f"{'='*50}")
    # nc captures full HTTP request, extract body
    lines = result.split("\n")
    in_body = False
    for line in lines:
        if in_body or not line.startswith(("POST", "Host:", "Content-")):
            in_body = True
            print(line.rstrip())
        if line.strip() == "":
            in_body = True
else:
    print("  No response received. Checking if nc captured anything...")
    si, so, se = c.exec_command("pct exec 112 -- ls -la /tmp/mc_result.txt", timeout=10)
    print(f"  {so.read().decode().strip()}")

c.close()
