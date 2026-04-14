#!/usr/bin/env python3
"""Install Node.js + MeshCentral on existing LXC 112."""
import paramiko
import time
import sys

PV1_HOST = "192.168.0.100"
PV1_USER = "root"
PV1_PASS = "CHANGE_ME"
MESH_ADMIN_PASS = "CHANGE_ME"

def ssh_exec(client, cmd, timeout=300):
    print(f"\n>>> {cmd[:150]}")
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    if out.strip():
        for line in out.strip().split("\n")[-20:]:
            print(f"  {line}")
    if rc != 0 and err.strip():
        print(f"  ERR(rc={rc}): {err.strip()[:200]}")
    return out, err, rc

def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(PV1_HOST, username=PV1_USER, password=PV1_PASS, timeout=10)

    # Step 1: Install Node.js 20
    print("=" * 60)
    print("STEP 1: Install Node.js 20")
    print("=" * 60)
    ssh_exec(client, "pct exec 112 -- apt-get update -qq", timeout=120)
    ssh_exec(client, "pct exec 112 -- apt-get install -y -qq curl ca-certificates gnupg", timeout=120)
    ssh_exec(client, "pct exec 112 -- bash -c 'curl -fsSL https://deb.nodesource.com/setup_20.x | bash -'", timeout=120)
    ssh_exec(client, "pct exec 112 -- apt-get install -y -qq nodejs", timeout=120)
    out, _, rc = ssh_exec(client, "pct exec 112 -- node --version")
    if rc != 0:
        print("FATAL: Node.js install failed")
        sys.exit(1)

    # Step 2: Install MeshCentral
    print("\n" + "=" * 60)
    print("STEP 2: Install MeshCentral")
    print("=" * 60)
    ssh_exec(client, "pct exec 112 -- mkdir -p /opt/meshcentral", timeout=10)
    ssh_exec(client, "pct exec 112 -- bash -c 'cd /opt/meshcentral && npm install meshcentral'", timeout=600)
    out, _, rc = ssh_exec(client, "pct exec 112 -- ls /opt/meshcentral/node_modules/meshcentral/meshcentral.js")
    if rc != 0:
        print("FATAL: MeshCentral npm install failed")
        sys.exit(1)

    # Step 3: Write config
    print("\n" + "=" * 60)
    print("STEP 3: Configure MeshCentral")
    print("=" * 60)
    ssh_exec(client, r"""pct exec 112 -- bash -c 'mkdir -p /opt/meshcentral/meshcentral-data && cat > /opt/meshcentral/meshcentral-data/config.json << EOFCFG
{
  "settings": {
    "cert": "meshcentral",
    "port": 443,
    "aliasPort": 443,
    "redirPort": 80,
    "selfUpdate": false
  },
  "domains": {
    "": {
      "title": "WinHunt MeshCentral",
      "newAccounts": false,
      "certUrl": "https://192.168.0.112/"
    }
  }
}
EOFCFG'""", timeout=10)

    # Step 4: Create + start systemd service
    print("\n" + "=" * 60)
    print("STEP 4: Create systemd service")
    print("=" * 60)
    ssh_exec(client, r"""pct exec 112 -- bash -c 'cat > /etc/systemd/system/meshcentral.service << EOFSVC
[Unit]
Description=MeshCentral Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/meshcentral
ExecStart=/usr/bin/node node_modules/meshcentral
Restart=always
RestartSec=10
User=root
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOFSVC
systemctl daemon-reload
systemctl enable --now meshcentral'""", timeout=30)

    print("\nWaiting 20s for MeshCentral first-start initialization...")
    time.sleep(20)

    # Step 5: Create admin account
    print("\n" + "=" * 60)
    print("STEP 5: Create admin account")
    print("=" * 60)
    # Stop service first — createaccount needs exclusive access
    ssh_exec(client, "pct exec 112 -- systemctl stop meshcentral", timeout=15)
    time.sleep(3)
    ssh_exec(client, f'pct exec 112 -- bash -c \'cd /opt/meshcentral && node node_modules/meshcentral --createaccount admin --pass "{MESH_ADMIN_PASS}" --domain ""\'', timeout=60)
    ssh_exec(client, "pct exec 112 -- systemctl start meshcentral", timeout=15)
    time.sleep(10)

    # Step 6: Verify
    print("\n" + "=" * 60)
    print("STEP 6: Verify")
    print("=" * 60)
    ssh_exec(client, "pct exec 112 -- systemctl is-active meshcentral")
    ssh_exec(client, "pct exec 112 -- curl -sk https://localhost/ -o /dev/null -w 'HTTP %{http_code}\\n'")
    ssh_exec(client, "pct exec 112 -- ss -tlnp | grep -E ':443|:80'")

    client.close()
    print("\n=== MeshCentral ready at https://192.168.0.112 ===")

if __name__ == "__main__":
    main()
