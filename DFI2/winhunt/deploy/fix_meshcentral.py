#!/usr/bin/env python3
"""Fix MeshCentral on existing LXC 112."""
import paramiko
import time
import sys

PV1_HOST = "192.168.0.100"
PV1_USER = "root"
PV1_PASS = "CHANGE_ME"
MESH_ADMIN_PASS = "CHANGE_ME"

def ssh_exec(client, cmd, timeout=300):
    print(f">>> {cmd[:120]}...")
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    if out.strip():
        print(out.strip())
    if err.strip():
        print(f"STDERR: {err.strip()}")
    return out, err, rc

def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(PV1_HOST, username=PV1_USER, password=PV1_PASS, timeout=10)

    # Check what's inside LXC 112
    print("=== Checking LXC 112 state ===")
    ssh_exec(client, "pct exec 112 -- ls -la /opt/meshcentral/ 2>/dev/null || echo 'DIR NOT FOUND'")
    ssh_exec(client, "pct exec 112 -- node --version 2>/dev/null || echo 'NODE NOT FOUND'")
    ssh_exec(client, "pct exec 112 -- cat /etc/systemd/system/meshcentral.service 2>/dev/null || echo 'SERVICE FILE NOT FOUND'")
    ssh_exec(client, "pct exec 112 -- ls /opt/meshcentral/node_modules/meshcentral/meshcentral.js 2>/dev/null || echo 'MESHCENTRAL NOT INSTALLED'")

    # Check if meshcentral npm package exists
    out, _, _ = ssh_exec(client, "pct exec 112 -- ls /opt/meshcentral/node_modules/meshcentral/ 2>/dev/null | head -5 || echo 'EMPTY'")

    if "EMPTY" in out or "NOT FOUND" in out or "NOT INSTALLED" in out:
        print("\n=== Installing Node.js + MeshCentral ===")
        install_cmd = """pct exec 112 -- bash -lc '
set -e
apt-get update -qq
apt-get install -y -qq curl ca-certificates
if ! command -v node &>/dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y -qq nodejs
fi
echo "Node: $(node --version)"
echo "npm: $(npm --version)"
mkdir -p /opt/meshcentral
cd /opt/meshcentral
npm install meshcentral 2>&1 | tail -5
echo "npm install done"
'"""
        ssh_exec(client, install_cmd, timeout=600)

    # Ensure config exists
    print("\n=== Ensuring MeshCentral config ===")
    config_cmd = """pct exec 112 -- bash -lc '
mkdir -p /opt/meshcentral/meshcentral-data
if [ ! -f /opt/meshcentral/meshcentral-data/config.json ]; then
cat > /opt/meshcentral/meshcentral-data/config.json << EOFCFG
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
EOFCFG
echo "Config created"
else
echo "Config already exists"
fi
cat /opt/meshcentral/meshcentral-data/config.json
'"""
    ssh_exec(client, config_cmd, timeout=30)

    # Ensure systemd service
    print("\n=== Ensuring systemd service ===")
    svc_cmd = """pct exec 112 -- bash -lc '
cat > /etc/systemd/system/meshcentral.service << EOFSVC
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
systemctl enable --now meshcentral
sleep 3
systemctl is-active meshcentral
'"""
    ssh_exec(client, svc_cmd, timeout=60)

    # Wait for initialization
    print("\nWaiting 15s for MeshCentral to initialize...")
    time.sleep(15)

    # Check if admin account exists, create if not
    print("\n=== Ensuring admin account ===")
    admin_cmd = f'pct exec 112 -- bash -lc \'cd /opt/meshcentral && node node_modules/meshcentral --createaccount admin --pass "{MESH_ADMIN_PASS}" --domain "" 2>&1 || echo "Account may already exist"\''
    ssh_exec(client, admin_cmd, timeout=60)

    # Final verification
    print("\n=== Final verification ===")
    ssh_exec(client, "pct exec 112 -- systemctl is-active meshcentral")
    ssh_exec(client, "pct exec 112 -- curl -sk https://localhost/ -o /dev/null -w 'HTTP %{http_code}\\n' 2>/dev/null || echo 'curl failed'")
    ssh_exec(client, "pct exec 112 -- ss -tlnp | grep -E '443|80'")

    client.close()
    print("\n=== Done. MeshCentral should be at https://192.168.0.112 ===")

if __name__ == "__main__":
    main()
