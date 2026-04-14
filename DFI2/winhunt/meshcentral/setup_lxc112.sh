#!/usr/bin/env bash
set -euo pipefail

CTID=112
HOSTNAME="meshcentral"
IP="192.168.0.112/24"
GW="192.168.0.1"
STORAGE="local-lvm"
TEMPLATE="local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.zst"
CORES=2
RAM=2048
DISK=10

pct create "$CTID" "$TEMPLATE" \
  --hostname "$HOSTNAME" \
  --cores "$CORES" \
  --memory "$RAM" \
  --rootfs "${STORAGE}:${DISK}" \
  --net0 "name=eth0,bridge=vmbr0,ip=${IP},gw=${GW}" \
  --unprivileged 1 \
  --features nesting=1 \
  --start 1 \
  --onboot 1

sleep 5

pct exec "$CTID" -- bash -lc '
apt-get update
apt-get install -y curl
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs
mkdir -p /opt/meshcentral
cd /opt/meshcentral
npm install meshcentral
mkdir -p meshcentral-data
cat > meshcentral-data/config.json <<EOF
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
EOF
cat > /etc/systemd/system/meshcentral.service <<EOF
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
EOF
systemctl daemon-reload
systemctl enable --now meshcentral
'

echo "MeshCentral ready at https://192.168.0.112"
