#!/usr/bin/env python3
"""Test meshctrl --reply directly with bash timeout wrapper."""
import paramiko, time

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("192.168.0.100", username="root", password="CHANGE_ME", timeout=10)

NODE = "node//rJxuIjVnZfALO8tHSCnolfbv3suKO0GhuhTBwHJJ170YIsgNVyRb2yfjwrgpWjvn"

script = f"""#!/bin/bash
cd /opt/meshcentral
echo "--- Start $(date) ---"
timeout 30 node node_modules/meshcentral/meshctrl.js runcommand \\
  --id "{NODE}" \\
  --run "Write-Output (Get-Date -Format o)" \\
  --powershell --reply \\
  --url wss://localhost \\
  --loginuser admin --loginpass "CHANGE_ME" 2>&1
RC=$?
echo "--- Exit code: $RC ---"
"""

si, so, _ = c.exec_command("pct exec 112 -- tee /tmp/_mc_test.sh > /dev/null", timeout=10)
si.write(script)
si.channel.shutdown_write()
so.read()

print("Running meshctrl --reply with bash timeout wrapper...")
si, so, se = c.exec_command("pct exec 112 -- bash /tmp/_mc_test.sh", timeout=60)
out = so.read().decode().strip()
err = se.read().decode().strip()
print("OUT:", out)
if err:
    print("ERR:", err[:300])
c.close()
