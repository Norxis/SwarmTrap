#!/usr/bin/env python3
"""Delete LXC 112 from PV1."""
import paramiko

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("192.168.0.100", username="root", password="CHANGE_ME", timeout=10)

def run(cmd):
    print(f"$ {cmd}")
    stdin, stdout, stderr = c.exec_command(cmd, timeout=30)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    rc = stdout.channel.recv_exit_status()
    if out: print(f"  {out}")
    if err: print(f"  ERR: {err}")
    return out, rc

# Check status
out, _ = run("pct status 112")

# Stop if running
if "running" in out:
    run("pct stop 112")
    import time; time.sleep(3)

# Destroy
run("pct destroy 112 --purge")

# Verify gone
run("pct list | grep 112 || echo 'CT112 deleted successfully'")

c.close()
