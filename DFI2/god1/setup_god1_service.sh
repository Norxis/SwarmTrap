#!/bin/bash
# Setup GOD 1 as systemd service on AIO
set -e

cp /tmp/god1_test.py /opt/dfi2/god1.py
echo "Installed /opt/dfi2/god1.py"

cat > /etc/systemd/system/dfi-god1.service << 'EOF'
[Unit]
Description=GOD 1 — AIO Instant Catcher (SPAN XGB Scorer)
After=network.target

[Service]
Type=simple
Environment=GOD1_IFACE=ens192
Environment=GOD1_MODEL=/opt/dfi2/ml/models/xgb_5class_v2.json
Environment=GOD1_TIMEOUT=120
Environment=GOD1_NATS=nats://192.168.0.100:4222
ExecStart=/usr/bin/python3 -u /opt/dfi2/god1.py
Restart=always
RestartSec=10
KillMode=control-group
MemoryMax=8G

[Install]
WantedBy=multi-user.target
EOF

pkill -f god1_test 2>/dev/null || true
pkill -f god1.py 2>/dev/null || true
systemctl daemon-reload
systemctl enable dfi-god1
systemctl start dfi-god1
sleep 3
echo "STATUS: $(systemctl is-active dfi-god1)"
journalctl -u dfi-god1 --no-pager -n 5
