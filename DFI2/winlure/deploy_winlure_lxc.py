#!/usr/bin/env python3
"""
deploy_winlure_lxc.py — Deploy Win-Lure + Trap + Watchlist Pusher LXC from CT110 base snapshot.

Clones CT110 (winlure_trap_base_v2) to a new CTID, configures networking,
persona, watchlist pusher self-IP ignore, and starts all 3 services.

Services:
    1. winlure        — AF_PACKET Windows persona (SMB, RDP, MSSQL, SSH, IIS, WinRM...)
    2. trap-honeypot  — 45 TCP + 15 UDP socket honeypots, all respond "this is a trap"
    3. watchlist-pusher — Tails logs, pushes attacker IPs to AIO watchlist (priority 1)

Usage:
    python3 deploy_winlure_lxc.py --ctid 130 --hostname FINANCE-DC01 \
        --lan-ip 172.16.3.130 --pub-ip 216.126.0.202/32 \
        --domain FINANCE.LOCAL --workgroup FINANCE

    python3 deploy_winlure_lxc.py --ctid 131 --hostname DEV-WEB01 \
        --lan-ip 172.16.3.131 --pub-ip 216.126.0.203/32 \
        --domain DEV.INTERNAL --workgroup DEV

Requirements:
    - Run from WSL2 (colo8gent@wsl2)
    - SSH key auth to PV1 (192.168.0.100) as root
    - CT110 must exist with snapshot 'winlure_trap_base_v2'
    - AIO reachable from LXC at 172.16.3.113:2222
"""

import argparse
import sys
import time

import paramiko

PV1_HOST = "192.168.0.100"
PV1_USER = "root"
PV1_KEY = "/home/colo8gent/.ssh/id_ed25519"
SOURCE_CTID = 110
SOURCE_SNAP = "winlure_trap_base_v2"
STORAGE = "local-lvm"


def ssh_connect():
    """Connect to PV1."""
    key = paramiko.Ed25519Key.from_private_key_file(PV1_KEY)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(PV1_HOST, port=22, username=PV1_USER, pkey=key, timeout=15)
    return client


def run(client, cmd, check=True):
    """Run command on PV1, return stdout."""
    stdin, stdout, stderr = client.exec_command(cmd, timeout=300)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    rc = stdout.channel.recv_exit_status()
    if check and rc != 0:
        print(f"FAIL [{rc}]: {cmd}")
        if err:
            print(f"  stderr: {err}")
        sys.exit(1)
    return out


def main():
    parser = argparse.ArgumentParser(description="Deploy Win-Lure + Trap LXC")
    parser.add_argument("--ctid", type=int, required=True, help="New container ID (e.g. 130)")
    parser.add_argument("--hostname", required=True, help="NetBIOS hostname (e.g. FINANCE-DC01, max 15 chars)")
    parser.add_argument("--lan-ip", required=True, help="LAN IP on v172 bridge (e.g. 172.16.3.130)")
    parser.add_argument("--pub-ip", required=True, help="Public IP with mask (e.g. 216.126.0.202/32)")
    parser.add_argument("--domain", default="CORP.LOCAL", help="AD domain name (default: CORP.LOCAL)")
    parser.add_argument("--workgroup", default="CORP", help="NetBIOS workgroup (default: CORP)")
    parser.add_argument("--cores", type=int, default=2, help="CPU cores (default: 2)")
    parser.add_argument("--memory", type=int, default=4096, help="RAM in MB (default: 4096)")
    parser.add_argument("--onboot", action="store_true", default=True, help="Start on boot (default: yes)")
    parser.add_argument("--no-onboot", action="store_false", dest="onboot")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing")
    args = parser.parse_args()

    ctid = args.ctid
    hostname = args.hostname.upper()
    lan_ip = args.lan_ip
    pub_ip = args.pub_ip
    domain = args.domain.upper()
    workgroup = args.workgroup.upper()

    # Validate
    if len(hostname) > 15:
        print(f"ERROR: hostname '{hostname}' exceeds 15 chars (NetBIOS limit)")
        sys.exit(1)
    if ctid == SOURCE_CTID:
        print(f"ERROR: cannot clone onto source CT {SOURCE_CTID}")
        sys.exit(1)

    print(f"=== Deploy Win-Lure + Trap Honeypot ===")
    print(f"  Source:    CT{SOURCE_CTID} @ {SOURCE_SNAP}")
    print(f"  Target:    CT{ctid}")
    print(f"  Hostname:  {hostname}")
    print(f"  LAN IP:    {lan_ip}")
    print(f"  Public IP: {pub_ip}")
    print(f"  Domain:    {domain} / {workgroup}")
    print(f"  Resources: {args.cores} cores, {args.memory}MB RAM")
    print()

    if args.dry_run:
        print("[DRY RUN] Would execute the following steps:")
        print(f"  1. pct clone {SOURCE_CTID} {ctid} --snapname {SOURCE_SNAP} --storage {STORAGE} --full")
        print(f"  2. pct set {ctid} --hostname {hostname.lower()} --cores {args.cores} --memory {args.memory}")
        print(f"  3. pct set {ctid} --net0 ... --ip {lan_ip}/24")
        print(f"  4. pct start {ctid}")
        print(f"  5. Configure winlure persona: {hostname}, {domain}")
        print(f"  6. Add public IP {pub_ip} to eth0")
        print(f"  7. Update winlure --ip to {pub_ip.split('/')[0]}")
        print(f"  8. Restart winlure + trap-honeypot")
        return

    client = ssh_connect()
    print("[1/8] Cloning CT110 snapshot → CT%d ..." % ctid)
    run(client, f"pct clone {SOURCE_CTID} {ctid} --snapname {SOURCE_SNAP} --storage {STORAGE} --full --description 'Win-Lure + Trap: {hostname}.{domain}'")

    print("[2/8] Configuring container settings ...")
    run(client, f"pct set {ctid} --hostname {hostname.lower()} --cores {args.cores} --memory {args.memory}")
    if args.onboot:
        run(client, f"pct set {ctid} --onboot 1 --startup order=10,up=30")

    print("[3/8] Configuring networking ...")
    mac = f"BC:24:11:{ctid:02X}:AA:01"
    run(client, f"pct set {ctid} --net0 name=eth0,bridge=v172,gw=172.16.3.1,hwaddr={mac},ip={lan_ip}/24,type=veth")

    print("[4/8] Starting container ...")
    run(client, f"pct start {ctid}")
    time.sleep(5)  # Wait for boot

    print("[5/8] Configuring persona ...")
    persona_yaml = f"/opt/winlure/winlure/config/personas/win2022_dc.yaml"
    # Update hostname, netbios, domain, workgroup, IP, DNS, target_name
    sed_cmds = [
        f"s/hostname: .*/hostname: {hostname}/",
        f"s/netbios_name: .*/netbios_name: {hostname}/",
        f"s/domain: .*/domain: {domain}/",
        f"s/workgroup: .*/workgroup: {workgroup}/",
        f"s|ip_address: .*|ip_address: {lan_ip}|",
        f"s/target_name: .*/target_name: {hostname}/",
    ]
    sed_expr = " ".join(f"-e '{s}'" for s in sed_cmds)
    run(client, f"pct exec {ctid} -- sed -i {sed_expr} {persona_yaml}")

    # Update DNS aliases
    dns_aliases = [
        f"{hostname.lower()}.{domain.lower()}",
        domain.lower(),
        f"_ldap._tcp.{domain.lower()}",
        f"_kerberos._tcp.{domain.lower()}",
        f"_gc._tcp.{domain.lower()}",
    ]
    # Replace dns_aliases block — clear old, write new
    run(client, f"pct exec {ctid} -- sed -i '/^  dns_aliases:/,/^  [a-z]/{{/^  dns_aliases:/!{{/^  [a-z]/!d}}}}' {persona_yaml}")
    for alias in dns_aliases:
        run(client, f"pct exec {ctid} -- sed -i '/^  dns_aliases:/a\\    - {alias}' {persona_yaml}")

    print("[6/8] Adding public IP ...")
    pub_addr = pub_ip.split("/")[0]
    run(client, f"pct exec {ctid} -- ip addr add {pub_ip} dev eth0")
    # Make persistent via networkd drop-in
    run(client, f"pct exec {ctid} -- bash -c 'mkdir -p /etc/networkd-dispatcher/routable.d && cat > /etc/networkd-dispatcher/routable.d/50-pub-ip.sh << INNER\n#!/bin/bash\nip addr add {pub_ip} dev eth0 2>/dev/null || true\nINNER\nchmod +x /etc/networkd-dispatcher/routable.d/50-pub-ip.sh'")

    print("[7/9] Updating winlure service IP ...")
    run(client, f"pct exec {ctid} -- sed -i 's/--ip [0-9.]*/--ip {pub_addr}/' /etc/systemd/system/winlure.service")
    run(client, f"pct exec {ctid} -- systemctl daemon-reload")

    print("[8/9] Updating watchlist pusher self-IP ignore ...")
    # Public IP is the only one that needs per-instance update
    # (RFC1918 subnets 192.168.*, 172.16.3.*, 10.* already ignored globally)
    pusher_py = "/opt/trap/watchlist_pusher.py"
    run(client, f"pct exec {ctid} -- sed -i 's/\"216.126.0.201\",.*# self public/\"{pub_addr}\",   # self public/' {pusher_py}")

    print("[9/9] Restarting all services ...")
    run(client, f"pct exec {ctid} -- systemctl restart winlure")
    run(client, f"pct exec {ctid} -- systemctl restart trap-honeypot")
    run(client, f"pct exec {ctid} -- systemctl restart watchlist-pusher")
    time.sleep(3)

    # Verify
    print()
    print("=== Verification ===")
    status_wl = run(client, f"pct exec {ctid} -- systemctl is-active winlure")
    status_trap = run(client, f"pct exec {ctid} -- systemctl is-active trap-honeypot")
    status_wlp = run(client, f"pct exec {ctid} -- systemctl is-active watchlist-pusher")
    ips = run(client, f"pct exec {ctid} -- ip -4 addr show eth0 | grep inet")
    tcp_count = run(client, f"pct exec {ctid} -- ss -tln | grep -c LISTEN", check=False)
    udp_count = run(client, f"pct exec {ctid} -- ss -uln | grep -c UNCONN", check=False)

    print(f"  winlure:           {status_wl}")
    print(f"  trap-honeypot:     {status_trap}")
    print(f"  watchlist-pusher:  {status_wlp}")
    print(f"  IPs:               {ips}")
    print(f"  TCP listeners:     {tcp_count}")
    print(f"  UDP listeners:     {udp_count}")

    all_active = status_wl == "active" and status_trap == "active" and status_wlp == "active"
    if all_active:
        print(f"\n  CT{ctid} ({hostname}) deployed successfully!")
        print(f"  Attacker IPs will auto-push to AIO watchlist (priority 1, depth 2)")
    else:
        print(f"\n  WARNING: One or more services not active. Check logs:")
        print(f"    pct exec {ctid} -- journalctl -u winlure -n 20 --no-pager")
        print(f"    pct exec {ctid} -- tail -20 /opt/trap/trap.log")
        print(f"    pct exec {ctid} -- tail -20 /opt/trap/watchlist_pusher.log")

    client.close()


if __name__ == "__main__":
    main()
