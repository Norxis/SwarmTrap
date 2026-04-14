#!/usr/bin/env python3
"""Step 1: Set up MeshCentral server on LXC 112 (PV1)."""
import paramiko
import time
import sys

PV1 = "192.168.0.100"
USER = "root"
PASS = "CHANGE_ME"
MESH_PASS = "CHANGE_ME"

def run(client, cmd, timeout=300, label=""):
    if label:
        print(f"\n[{label}]")
    print(f"  $ {cmd[:200]}")
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    rc = stdout.channel.recv_exit_status()
    if out:
        for line in out.split("\n")[-25:]:
            print(f"  {line}")
    if rc != 0 and err:
        print(f"  ERR(rc={rc}): {err[:300]}")
    return out, err, rc

def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(PV1, username=USER, password=PASS, timeout=10)

    # 1. Check LXC 112 status
    out, _, _ = run(c, "pct status 112 2>/dev/null || echo 'NOT_FOUND'", label="LXC status")
    if "NOT_FOUND" in out:
        print("LXC 112 does not exist. Creating...")
        # Check template
        out, _, _ = run(c, "ls /var/lib/vz/template/cache/ | grep ubuntu-22.04 || echo NONE")
        if "NONE" in out:
            print("Downloading template...")
            run(c, "pveam download local ubuntu-22.04-standard_22.04-1_amd64.tar.zst", timeout=600, label="Download template")

        run(c, (
            "pct create 112 local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.zst "
            "--hostname meshcentral --cores 2 --memory 2048 "
            "--rootfs local-lvm:10 "
            "--net0 name=eth0,bridge=vmbr0,ip=192.168.0.112/24,gw=192.168.0.1 "
            "--unprivileged 1 --features nesting=1 --start 1 --onboot 1"
        ), timeout=120, label="Create LXC")
        time.sleep(8)
    elif "stopped" in out:
        run(c, "pct start 112", label="Start LXC")
        time.sleep(5)

    # 2. Fix IPv6 issue — force apt to use IPv4
    run(c, """pct exec 112 -- bash -c 'echo "Acquire::ForceIPv4 \\"true\\";" > /etc/apt/apt.conf.d/99force-ipv4'""",
        label="Force apt IPv4")

    # Also set DNS to use Google DNS (IPv4 only)
    run(c, """pct exec 112 -- bash -c 'echo "nameserver 8.8.8.8" > /etc/resolv.conf'""",
        label="Set DNS")

    # 3. Test connectivity
    out, _, rc = run(c, "pct exec 112 -- bash -c 'ping -c 1 -W 3 8.8.8.8 2>&1 | tail -2'", label="Test ping")
    if rc != 0:
        print("ERROR: LXC 112 cannot reach internet. Check gateway/bridge config.")
        sys.exit(1)

    out, _, rc = run(c, "pct exec 112 -- bash -c 'curl -sI http://archive.ubuntu.com 2>&1 | head -3'", label="Test HTTP")

    # 4. Install packages
    run(c, "pct exec 112 -- apt-get update -qq", timeout=120, label="apt update")
    run(c, "pct exec 112 -- apt-get install -y -qq curl ca-certificates gnupg", timeout=120, label="Install deps")

    # 5. Install Node.js 20
    out, _, rc = run(c, "pct exec 112 -- node --version 2>/dev/null", label="Check Node")
    if rc != 0:
        run(c, "pct exec 112 -- bash -c 'curl -fsSL https://deb.nodesource.com/setup_20.x | bash -'",
            timeout=120, label="Setup NodeSource")
        run(c, "pct exec 112 -- apt-get install -y -qq nodejs", timeout=120, label="Install Node.js")

    out, _, rc = run(c, "pct exec 112 -- node --version", label="Verify Node")
    if rc != 0:
        print("FATAL: Node.js not installed")
        sys.exit(1)

    # 6. Install MeshCentral
    out, _, rc = run(c, "pct exec 112 -- ls /opt/meshcentral/node_modules/meshcentral/meshcentral.js 2>/dev/null", label="Check MC")
    if rc != 0:
        run(c, "pct exec 112 -- mkdir -p /opt/meshcentral", label="mkdir")
        run(c, "pct exec 112 -- bash -c 'cd /opt/meshcentral && npm install meshcentral'",
            timeout=600, label="npm install meshcentral")

    out, _, rc = run(c, "pct exec 112 -- ls /opt/meshcentral/node_modules/meshcentral/meshcentral.js", label="Verify MC")
    if rc != 0:
        print("FATAL: MeshCentral not installed")
        sys.exit(1)

    # 7. Configure MeshCentral
    run(c, """pct exec 112 -- bash -c 'mkdir -p /opt/meshcentral/meshcentral-data && cat > /opt/meshcentral/meshcentral-data/config.json << EOF
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
EOF'""", label="Write MC config")

    # 8. Create systemd service
    run(c, """pct exec 112 -- bash -c 'cat > /etc/systemd/system/meshcentral.service << EOF
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
systemctl enable meshcentral'""", label="Create service")

    # 9. Start MeshCentral (first time — generates certs)
    run(c, "pct exec 112 -- systemctl restart meshcentral", label="Start MC")
    print("\n  Waiting 20s for MeshCentral first-start (cert generation)...")
    time.sleep(20)

    # 10. Check if running
    out, _, rc = run(c, "pct exec 112 -- systemctl is-active meshcentral", label="Check service")
    if "active" not in out:
        print("  Service not active, checking logs...")
        run(c, "pct exec 112 -- journalctl -u meshcentral -n 20 --no-pager", label="Service logs")
        # Try once more
        run(c, "pct exec 112 -- systemctl restart meshcentral", label="Restart MC")
        time.sleep(15)
        out, _, _ = run(c, "pct exec 112 -- systemctl is-active meshcentral", label="Recheck")

    # 11. Create admin account
    run(c, "pct exec 112 -- systemctl stop meshcentral", label="Stop MC for account creation")
    time.sleep(3)
    run(c, f"""pct exec 112 -- bash -c 'cd /opt/meshcentral && node node_modules/meshcentral --createaccount admin --pass "{MESH_PASS}" --domain "" 2>&1 | tail -5'""",
        timeout=60, label="Create admin")
    run(c, "pct exec 112 -- systemctl start meshcentral", label="Start MC")
    time.sleep(10)

    # 12. Final verify
    print("\n" + "=" * 50)
    print("VERIFICATION")
    print("=" * 50)
    run(c, "pct exec 112 -- systemctl is-active meshcentral", label="Service status")
    run(c, "pct exec 112 -- ss -tlnp | grep -E ':443|:80'", label="Listening ports")
    run(c, "pct exec 112 -- curl -sk https://localhost/ -o /dev/null -w 'HTTP %{http_code}\\n'", label="HTTP check")

    c.close()
    print("\n" + "=" * 50)
    print("MeshCentral server ready at https://192.168.0.112")
    print("Login: admin / CHANGE_ME")
    print("=" * 50)

if __name__ == "__main__":
    main()
