#!/usr/bin/env python3
"""Create MeshCentral LXC 112 on PV1 via SSH (paramiko)."""
import paramiko
import time
import sys

PV1_HOST = "192.168.0.100"
PV1_USER = "root"
PV1_PASS = "CHANGE_ME"
MESH_ADMIN_PASS = "CHANGE_ME"

def ssh_exec(client, cmd, timeout=300):
    """Execute command and return stdout, stderr."""
    print(f">>> {cmd[:120]}...")
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    if out.strip():
        print(out.strip())
    if err.strip() and rc != 0:
        print(f"STDERR: {err.strip()}", file=sys.stderr)
    return out, err, rc

def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(PV1_HOST, username=PV1_USER, password=PV1_PASS, timeout=10)

    # Check if LXC 112 already exists
    out, _, _ = ssh_exec(client, "pct list 2>/dev/null | grep -c '^112 ' || echo 0")
    if out.strip() != "0":
        print("LXC 112 already exists, checking status...")
        out, _, _ = ssh_exec(client, "pct status 112")
        print(f"Status: {out.strip()}")
        if "running" in out:
            print("Already running. Checking MeshCentral...")
            out, _, _ = ssh_exec(client, "pct exec 112 -- systemctl is-active meshcentral 2>/dev/null || echo inactive")
            print(f"MeshCentral service: {out.strip()}")
        client.close()
        return

    # Check if template exists
    out, _, rc = ssh_exec(client, "ls /var/lib/vz/template/cache/ | grep ubuntu-22.04")
    if not out.strip():
        print("Downloading Ubuntu 22.04 template...")
        ssh_exec(client, "pveam download local ubuntu-22.04-standard_22.04-1_amd64.tar.zst", timeout=600)

    # Create LXC
    print("\n=== Creating LXC 112 ===")
    create_cmd = (
        "pct create 112 local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.zst "
        "--hostname meshcentral "
        "--cores 2 --memory 2048 "
        "--rootfs local-lvm:10 "
        "--net0 name=eth0,bridge=vmbr0,ip=192.168.0.112/24,gw=192.168.0.1 "
        "--unprivileged 1 --features nesting=1 "
        "--start 1 --onboot 1"
    )
    out, err, rc = ssh_exec(client, create_cmd, timeout=120)
    if rc != 0:
        print(f"FAILED to create LXC: {err}")
        client.close()
        sys.exit(1)

    print("Waiting for LXC to start...")
    time.sleep(10)

    # Install Node.js + MeshCentral
    print("\n=== Installing Node.js 20 + MeshCentral ===")
    install_cmd = """pct exec 112 -- bash -lc '
set -e
apt-get update -qq
apt-get install -y -qq curl ca-certificates
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y -qq nodejs
node --version
npm --version
mkdir -p /opt/meshcentral
cd /opt/meshcentral
npm install meshcentral 2>&1 | tail -3
echo "MeshCentral npm install done"
'"""
    ssh_exec(client, install_cmd, timeout=600)

    # Configure MeshCentral
    print("\n=== Configuring MeshCentral ===")
    config_cmd = """pct exec 112 -- bash -lc '
mkdir -p /opt/meshcentral/meshcentral-data
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
echo "MeshCentral service started"
'"""
    ssh_exec(client, config_cmd, timeout=120)

    # Wait for MeshCentral to initialize
    print("\nWaiting 15s for MeshCentral to initialize...")
    time.sleep(15)

    # Create admin account
    print("\n=== Creating admin account ===")
    admin_cmd = f'pct exec 112 -- bash -lc \'cd /opt/meshcentral && node node_modules/meshcentral --createaccount admin --pass "{MESH_ADMIN_PASS}" --domain ""\''
    ssh_exec(client, admin_cmd, timeout=60)

    # Verify
    print("\n=== Verification ===")
    ssh_exec(client, "pct exec 112 -- systemctl is-active meshcentral")
    ssh_exec(client, "pct exec 112 -- curl -sk https://localhost/ -o /dev/null -w 'HTTP %{http_code}\\n'")

    client.close()
    print("\n=== MeshCentral ready at https://192.168.0.112 ===")

if __name__ == "__main__":
    main()
