#!/usr/bin/env python3
"""Fix MeshCentral config to use 172.16.3.112."""
import paramiko
import json
import time

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("192.168.0.100", username="root", password="CHANGE_ME", timeout=10)

def run(cmd, timeout=30):
    print(f"$ {cmd[:180]}")
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if out: print(f"  {out}")
    if err: print(f"  ERR: {err}")
    return out

config = {
    "settings": {
        "cert": "meshcentral",
        "port": 443,
        "aliasPort": 443,
        "redirPort": 80,
        "selfUpdate": False,
        "tlsOffload": False
    },
    "domains": {
        "": {
            "title": "WinHunt MeshCentral",
            "newAccounts": False,
            "certUrl": "https://172.16.3.112/"
        }
    }
}

config_json = json.dumps(config, indent=2)

# Write config via stdin to avoid escaping issues
print("\nWriting config...")
stdin, stdout, stderr = c.exec_command(
    "pct exec 112 -- tee /opt/meshcentral/meshcentral-data/config.json > /dev/null",
    timeout=10
)
stdin.write(config_json)
stdin.channel.shutdown_write()
out = stdout.read().decode().strip()
err = stderr.read().decode().strip()
if err: print(f"  ERR: {err}")

# Verify config was written correctly
run("pct exec 112 -- cat /opt/meshcentral/meshcentral-data/config.json")

# Delete old certs so MeshCentral regenerates with new certUrl
print("\nRemoving old certs for regeneration...")
run("pct exec 112 -- rm -f /opt/meshcentral/meshcentral-data/webserver-cert-public.crt")
run("pct exec 112 -- rm -f /opt/meshcentral/meshcentral-data/webserver-cert-private.key")

# Restart MeshCentral
print("\nRestarting MeshCentral...")
run("pct exec 112 -- systemctl restart meshcentral")

print("\nWaiting 15s for cert regeneration + startup...")
time.sleep(15)

# Verify
run("pct exec 112 -- systemctl is-active meshcentral")
run("pct exec 112 -- ss -tlnp | grep :443")
run("pct exec 112 -- curl -sk https://172.16.3.112/ -o /dev/null -w 'HTTP %{http_code}\\n'")
run("pct exec 112 -- curl -sk https://192.168.0.112/ -o /dev/null -w 'HTTP %{http_code}\\n'")

c.close()
print("\nDone — MeshCentral accessible on both 192.168.0.112 and 172.16.3.112")
