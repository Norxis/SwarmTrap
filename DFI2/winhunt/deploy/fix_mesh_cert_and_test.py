#!/usr/bin/env python3
"""Fix MeshCentral cert for 172.16.3.112 + test command execution."""
import paramiko
import time

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("192.168.0.100", username="root", password="CHANGE_ME", timeout=10)

def run(cmd, timeout=30):
    print(f"\n$ {cmd[:180]}")
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if out: print(f"  {out}")
    if err: print(f"  ERR: {err}")
    return out

meshctrl = "/opt/meshcentral/node_modules/meshcentral/meshctrl.js"
mbase = '--url wss://localhost --loginuser admin --loginpass "CHANGE_ME"'

# Check current cert — what hostname/IPs it covers
print("=" * 50)
print("CHECK: Current cert SANs")
print("=" * 50)
run("pct exec 112 -- openssl x509 -in /opt/meshcentral/meshcentral-data/webserver-cert-public.crt -text -noout 2>/dev/null | grep -A5 'Subject Alternative'")
run("pct exec 112 -- openssl x509 -in /opt/meshcentral/meshcentral-data/webserver-cert-public.crt -subject -noout")

# Delete all certs and restart to force regeneration with certUrl=172.16.3.112
print("\n" + "=" * 50)
print("FIX: Regenerate certs for 172.16.3.112")
print("=" * 50)
run("pct exec 112 -- systemctl stop meshcentral")
time.sleep(3)

# Remove all cert files
run("pct exec 112 -- rm -f /opt/meshcentral/meshcentral-data/*.crt /opt/meshcentral/meshcentral-data/*.key")

# Verify config has correct certUrl
run("pct exec 112 -- cat /opt/meshcentral/meshcentral-data/config.json")

# Start MeshCentral — it will regenerate certs
run("pct exec 112 -- systemctl start meshcentral")
print("\nWaiting 25s for cert regeneration + startup...")
time.sleep(25)

# Check new cert
run("pct exec 112 -- openssl x509 -in /opt/meshcentral/meshcentral-data/webserver-cert-public.crt -text -noout 2>/dev/null | grep -A5 'Subject Alternative'")
run("pct exec 112 -- openssl x509 -in /opt/meshcentral/meshcentral-data/webserver-cert-public.crt -subject -noout")
run("pct exec 112 -- systemctl is-active meshcentral")
run("pct exec 112 -- curl -sk https://172.16.3.112/ -o /dev/null -w 'HTTP %{http_code}\\n'")

# Check logs for cert error
run("pct exec 112 -- journalctl -u meshcentral --no-pager -n 10 | grep -i -E 'cert|error|fail|agent'")

# Wait for agent to reconnect
print("\nWaiting 15s for agent reconnect...")
time.sleep(15)

# List devices
print("\n" + "=" * 50)
print("CHECK: MeshCentral devices")
print("=" * 50)
run(f'pct exec 112 -- node {meshctrl} {mbase} listdevices --group "WinHunt-Test" 2>&1')
run(f'pct exec 112 -- node {meshctrl} {mbase} listdevices 2>&1')

# Try running a command
print("\n" + "=" * 50)
print("TEST: Execute command on 172.16.3.160 via MeshCentral")
print("=" * 50)

# First get any device ID
out = run(f'pct exec 112 -- node {meshctrl} {mbase} listdevices --json 2>&1')
import json
try:
    devices = json.loads(out)
    if devices:
        node_id = devices[0].get("_id", "")
        print(f"\n  Found device: {node_id}")
        # Run test command
        run(f'pct exec 112 -- node {meshctrl} {mbase} runcommand --id "{node_id}" --run "hostname" 2>&1')
        time.sleep(3)
        run(f'pct exec 112 -- node {meshctrl} {mbase} runcommand --id "{node_id}" --run "ipconfig" 2>&1')
    else:
        print("\n  No devices found yet.")
except json.JSONDecodeError:
    print(f"\n  Could not parse device list: {out[:200]}")

c.close()
