#!/usr/bin/env python3
"""Test fire-and-forget approach: run command that writes to file, then download."""
import paramiko, time, json

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("192.168.0.100", username="root", password="CHANGE_ME", timeout=10)

NODE = "node//rJxuIjVnZfALO8tHSCnolfbv3suKO0GhuhTBwHJJ170YIsgNVyRb2yfjwrgpWjvn"

# Step 1: Fire-and-forget — command writes output to C:\TEMP\mc_out.txt
ps_cmd = (
    'Get-Date -Format o | Out-File C:\\TEMP\\mc_out.txt -Encoding utf8; '
    'Get-Service WinHuntAgent | Format-List Name,Status | Out-File C:\\TEMP\\mc_out.txt -Append -Encoding utf8; '
    'Get-Process python -ErrorAction SilentlyContinue | Select Id,WorkingSet64,StartTime | Format-List | Out-File C:\\TEMP\\mc_out.txt -Append -Encoding utf8'
)

script = f"""#!/bin/bash
cd /opt/meshcentral
node node_modules/meshcentral/meshctrl.js runcommand \\
  --id "{NODE}" \\
  --run "{ps_cmd}" \\
  --powershell \\
  --url wss://localhost \\
  --loginuser admin --loginpass "CHANGE_ME" 2>&1
"""

si, so, _ = c.exec_command("pct exec 112 -- tee /tmp/_mc_faf.sh > /dev/null", timeout=10)
si.write(script)
si.channel.shutdown_write()
so.read()

print("Step 1: Fire-and-forget command...")
si, so, se = c.exec_command("pct exec 112 -- bash /tmp/_mc_faf.sh", timeout=30)
out = so.read().decode().strip()
print(f"  Result: {out}")

# Wait for command to execute on Windows
print("Step 2: Waiting 10s for command to execute on Windows...")
time.sleep(10)

# Step 3: Download the output file
print("Step 3: Downloading output file...")
dl_script = f"""#!/bin/bash
cd /opt/meshcentral
node node_modules/meshcentral/meshctrl.js download \\
  --id "{NODE}" \\
  --file "C:\\\\TEMP\\\\mc_out.txt" \\
  --target "/tmp/mc_out.txt" \\
  --url wss://localhost \\
  --loginuser admin --loginpass "CHANGE_ME" 2>&1
"""

si, so, _ = c.exec_command("pct exec 112 -- tee /tmp/_mc_dl.sh > /dev/null", timeout=10)
si.write(dl_script)
si.channel.shutdown_write()
so.read()

si, so, se = c.exec_command("pct exec 112 -- bash /tmp/_mc_dl.sh", timeout=30)
out = so.read().decode().strip()
print(f"  Download result: {out}")

# Read the downloaded file
si, so, se = c.exec_command("pct exec 112 -- cat /tmp/mc_out.txt", timeout=10)
content = so.read().decode().strip()
print(f"\n=== Output from Windows ===\n{content}")

c.close()
