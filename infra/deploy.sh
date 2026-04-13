#!/usr/bin/env bash
set -euo pipefail

REMOTE="colo8gent@192.168.0.200"
JUMP="root@192.168.0.215"
SSH="ssh -o ProxyJump=$JUMP $REMOTE"
SCP="scp -o ProxyJump=$JUMP"

echo "=== SwarmTrap.net deploy ==="

# 1. Upload static site
echo "[1/6] Uploading static site..."
$SCP -r site/* "$REMOTE:/opt/swarmtrap/site/"

# 2. Upload proxy
echo "[2/6] Uploading proxy..."
$SCP proxy/proxy.py "$REMOTE:/opt/swarmtrap/proxy/proxy.py"

# 3. Upload dashboard build
echo "[3/6] Uploading SOC dashboard build..."
$SSH "rm -rf /opt/swarmtrap/dashboard/dist"
$SCP -r dashboard/dist "$REMOTE:/opt/swarmtrap/dashboard/dist"

# 4. Upload founding documents
echo "[4/6] Uploading founding documents..."
$SCP SwarmTrap_Founding_Document_v4.md "$REMOTE:/opt/swarmtrap/docs/"
$SCP Foundation_v0_1_Complete_Design.md "$REMOTE:/opt/swarmtrap/docs/"
$SCP Open_Utopia_Framework_v4.md "$REMOTE:/opt/swarmtrap/docs/"

# 5. Upload Caddy config + systemd unit
echo "[5/6] Uploading infra config..."
$SCP infra/Caddyfile "$REMOTE:/tmp/Caddyfile"
$SCP infra/swarmtrap-proxy.service "$REMOTE:/tmp/swarmtrap-proxy.service"
$SSH "sudo cp /tmp/Caddyfile /etc/caddy/Caddyfile"
$SSH "sudo cp /tmp/swarmtrap-proxy.service /etc/systemd/system/swarmtrap-proxy.service"

# 6. Restart services
echo "[6/6] Restarting services..."
$SSH "sudo systemctl daemon-reload"
$SSH "sudo systemctl enable --now swarmtrap-proxy"
$SSH "sudo systemctl restart swarmtrap-proxy"
$SSH "sudo systemctl restart caddy"

echo "=== Deploy complete ==="
echo "Test: https://swarmtrap.net"
echo "Test: https://swarmtrap.net/thesis"
echo "Test: https://swarmtrap.net/proof"
echo "Test: https://swarmtrap.net/join"
echo "Test: https://swarmtrap.net/dashboard/"
