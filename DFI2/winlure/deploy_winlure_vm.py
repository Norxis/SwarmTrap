#!/usr/bin/env python3
"""
deploy_winlure_vm.py — Deploy Win-Lure + Trap + Watchlist Pusher in LXC inside Ubuntu 24.04 VMs.

PROVEN PROCESS from VM 200 manual deploy (2026-03-16):
    1. PV1: create VM with cloud-init, static IP, WSL key
    2. WSL: SCP tarballs to VM
    3. WSL: SSH to VM, run LXD/LXC/winlure setup
    All commands are EXACT copies from the working VM 200 session.

CRITICAL SAFETY:
    - Winlure runs INSIDE LXC container (isolated network namespace)
    - SSH moved to 2222 inside container BEFORE winlure starts
    - Host VM SSH on port 22 is never touched

Usage:
    python3 deploy_winlure_vm.py --start 0 --count 1  # Test ONE first
    python3 deploy_winlure_vm.py --start 1 --count 9  # Then the rest
"""

import argparse
import subprocess
import sys
import time
import os

PV1 = "root@192.168.0.100"
KEY = os.path.expanduser("~/.ssh/id_ed25519")
CLOUD_IMG = "/mnt/dfi-data/iso/noble-server-cloudimg-amd64.img"
STORAGE = "NV2T-2"

PUB_SUBNET = "38.247.143"
PUB_MASK = 24
PUB_GW = "38.247.143.1"

VMS = [
    {"vmid": 200, "name": "winlure-01", "hostname": "EXCHANGE-01",  "domain": "CORP.LOCAL",     "workgroup": "CORP",    "pub_ip": f"{PUB_SUBNET}.165", "mgmt_ip": "172.16.3.200"},
    {"vmid": 201, "name": "winlure-02", "hostname": "BACKUP-DC01",  "domain": "CORP.LOCAL",     "workgroup": "CORP",    "pub_ip": f"{PUB_SUBNET}.30",  "mgmt_ip": "172.16.3.201"},
    {"vmid": 202, "name": "winlure-03", "hostname": "HR-SQL01",     "domain": "HR.INTERNAL",    "workgroup": "HR",      "pub_ip": f"{PUB_SUBNET}.8",   "mgmt_ip": "172.16.3.202"},
    {"vmid": 203, "name": "winlure-04", "hostname": "FIN-DC01",     "domain": "FINANCE.LOCAL",  "workgroup": "FINANCE", "pub_ip": f"{PUB_SUBNET}.191", "mgmt_ip": "172.16.3.203"},
    {"vmid": 204, "name": "winlure-05", "hostname": "DEV-BUILD01",  "domain": "DEV.INTERNAL",   "workgroup": "DEV",     "pub_ip": f"{PUB_SUBNET}.72",  "mgmt_ip": "172.16.3.204"},
    {"vmid": 205, "name": "winlure-06", "hostname": "IT-MGMT01",    "domain": "IT.CORP.LOCAL",  "workgroup": "IT",      "pub_ip": f"{PUB_SUBNET}.64",  "mgmt_ip": "172.16.3.205"},
    {"vmid": 206, "name": "winlure-07", "hostname": "WEB-IIS01",    "domain": "DMZ.LOCAL",      "workgroup": "DMZ",     "pub_ip": f"{PUB_SUBNET}.59",  "mgmt_ip": "172.16.3.206"},
    {"vmid": 207, "name": "winlure-08", "hostname": "SQL-PROD01",   "domain": "PROD.INTERNAL",  "workgroup": "PROD",    "pub_ip": f"{PUB_SUBNET}.37",  "mgmt_ip": "172.16.3.211"},
    {"vmid": 208, "name": "winlure-09", "hostname": "PRINT-SRV01",  "domain": "CORP.LOCAL",     "workgroup": "CORP",    "pub_ip": f"{PUB_SUBNET}.190", "mgmt_ip": "172.16.3.214"},
    {"vmid": 209, "name": "winlure-10", "hostname": "VPN-GW01",     "domain": "EDGE.LOCAL",     "workgroup": "EDGE",    "pub_ip": f"{PUB_SUBNET}.28",  "mgmt_ip": "172.16.3.215"},
]


def run(cmd, check=True, timeout=300):
    """Run shell command, print and check result."""
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0 and check:
        print(f"  FAIL [{r.returncode}]: {cmd[:120]}")
        if r.stderr:
            print(f"  stderr: {r.stderr[:300]}")
        return False
    return True


def ssh_pv1(cmd, check=True, timeout=300):
    """Run command on PV1 via SSH."""
    return run(f"ssh -i {KEY} -o StrictHostKeyChecking=no {PV1} \"{cmd}\"", check=check, timeout=timeout)


def ssh_vm(ip, cmd, check=True, timeout=300):
    """Run command on VM via SSH (exact VM 200 pattern)."""
    full = (
        f"ssh -i {KEY} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null colo8gent@{ip} "
        f"\"echo 'CHANGE_ME' | sudo -S true 2>/dev/null && {cmd}\""
    )
    return run(full, check=check, timeout=timeout)


def scp_to_vm(ip, src, dst):
    """SCP from WSL to VM (exact VM 200 pattern — NOT via PV1)."""
    return run(f"scp -i {KEY} -o StrictHostKeyChecking=no {src} colo8gent@{ip}:{dst}")


def wait_ssh(ip, max_wait=180):
    """Wait for SSH to be stable (connect twice with 10s gap to survive cloud-init reboots)."""
    start = time.time()
    while time.time() - start < max_wait:
        r = subprocess.run(
            f"ssh -i {KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=5 colo8gent@{ip} echo OK",
            shell=True, capture_output=True, text=True, timeout=15
        )
        if r.returncode == 0:
            time.sleep(10)  # Wait for cloud-init reboot
            r2 = subprocess.run(
                f"ssh -i {KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=5 colo8gent@{ip} echo OK",
                shell=True, capture_output=True, text=True, timeout=15
            )
            if r2.returncode == 0:
                return True
        time.sleep(5)
    return False


def pack_source():
    """Pack winlure source from CT110 to PV1 /tmp/ (once)."""
    print("[PACK] Packing from CT110 ...")
    ssh_pv1("pct exec 110 -- tar czf /tmp/winlure_full.tar.gz -C /opt winlure/winlure trap/trap_honeypot.py trap/watchlist_pusher.py")
    ssh_pv1("pct exec 110 -- tar czf /tmp/winlure_configs.tar.gz -C / etc/systemd/system/winlure.service etc/systemd/system/trap-honeypot.service etc/systemd/system/watchlist-pusher.service etc/sysctl.d/99-winlure.conf")
    ssh_pv1("pct pull 110 /tmp/winlure_full.tar.gz /tmp/winlure_full.tar.gz")
    ssh_pv1("pct pull 110 /tmp/winlure_configs.tar.gz /tmp/winlure_configs.tar.gz")
    # Pull to WSL (proven: WSL→VM SCP, not PV1→VM)
    run(f"scp -i {KEY} -o StrictHostKeyChecking=no {PV1}:/tmp/winlure_full.tar.gz /tmp/")
    run(f"scp -i {KEY} -o StrictHostKeyChecking=no {PV1}:/tmp/winlure_configs.tar.gz /tmp/")
    # Upload WSL public key to PV1 for cloud-init
    run(f"scp -i {KEY} -o StrictHostKeyChecking=no {KEY}.pub {PV1}:/tmp/wsl_key.pub")
    print("  Done")


def create_vm(vm):
    """Create VM on PV1 (exact VM 200 pattern)."""
    v = vm["vmid"]
    n = vm["name"]
    ip = vm["mgmt_ip"]
    print(f"\n{'='*60}")
    print(f"[VM {v}] Creating {n} @ {ip} ...")

    if not ssh_pv1(f"qm create {v} --name {n} --ostype l26 --cpu host --cores 2 --sockets 1 --memory 4096 --scsihw virtio-scsi-single --net0 virtio,bridge=v172,firewall=0 --serial0 socket --agent 1 --onboot 1"):
        return False
    if not ssh_pv1(f"qm importdisk {v} {CLOUD_IMG} {STORAGE}", timeout=120):
        return False
    if not ssh_pv1(f"qm set {v} --scsi0 {STORAGE}:vm-{v}-disk-0,iothread=1,ssd=1"):
        return False
    if not ssh_pv1(f"qm set {v} --boot order=scsi0"):
        return False
    if not ssh_pv1(f"qm resize {v} scsi0 32G"):
        return False
    if not ssh_pv1(f"qm set {v} --ide2 {STORAGE}:cloudinit"):
        return False
    if not ssh_pv1(f"qm set {v} --ciuser colo8gent --cipassword CHANGE_ME"):
        return False
    if not ssh_pv1(f"qm set {v} --nameserver '8.8.8.8 1.1.1.1'"):
        return False
    if not ssh_pv1(f"qm set {v} --ipconfig0 ip={ip}/24,gw=172.16.3.1"):
        return False
    if not ssh_pv1(f"qm set {v} --sshkeys /tmp/wsl_key.pub"):
        return False
    if not ssh_pv1(f"qm start {v}"):
        return False
    print(f"  VM started, waiting for SSH ...", end="", flush=True)
    if not wait_ssh(ip):
        print(" TIMEOUT")
        return False
    print(" OK")
    return True


def deploy_in_vm(vm):
    """Deploy winlure stack in VM (exact VM 200 commands)."""
    v = vm["vmid"]
    ip = vm["mgmt_ip"]
    pub = vm["pub_ip"]
    hostname = vm["hostname"]
    domain = vm["domain"]
    workgroup = vm["workgroup"]

    print(f"[VM {v}] Deploying (pub: {pub}) ...")

    # Step 1: SCP tarballs + WSL key from WSL to VM (PROVEN: WSL→VM, not PV1→VM)
    if not scp_to_vm(ip, "/tmp/winlure_full.tar.gz /tmp/winlure_configs.tar.gz", "/tmp/"):
        return False
    if not scp_to_vm(ip, KEY, "/tmp/wsl_key"):
        return False
    print(f"  Files copied to VM")

    # Step 2: Install LXD (exact VM 200)
    if not ssh_vm(ip, "sudo snap install lxd 2>&1 | tail -1", timeout=180):
        return False
    if not ssh_vm(ip, "sudo lxd init --auto"):
        return False
    print(f"  LXD installed")

    # Step 3: Create LXC container (exact VM 200)
    if not ssh_vm(ip, "sudo lxc launch ubuntu:22.04 winlure 2>&1 | tail -1", timeout=180):
        return False
    time.sleep(10)
    print(f"  LXC container created")

    # Step 4: Push tarballs into container (exact VM 200)
    if not ssh_vm(ip, "sudo lxc file push /tmp/winlure_full.tar.gz winlure/tmp/"):
        return False
    if not ssh_vm(ip, "sudo lxc file push /tmp/winlure_configs.tar.gz winlure/tmp/"):
        return False
    if not ssh_vm(ip, "sudo lxc exec winlure -- mkdir -p /opt/winlure/state /opt/trap"):
        return False
    if not ssh_vm(ip, "sudo lxc exec winlure -- tar xzf /tmp/winlure_full.tar.gz -C /opt"):
        return False
    if not ssh_vm(ip, "sudo lxc exec winlure -- tar xzf /tmp/winlure_configs.tar.gz -C /"):
        return False
    print(f"  Files extracted in container")

    # Step 5: Python deps (exact VM 200)
    if not ssh_vm(ip, "sudo lxc exec winlure -- bash -c 'apt-get update -qq && apt-get install -y -qq python3-venv python3-pip > /dev/null 2>&1'", timeout=180):
        return False
    if not ssh_vm(ip, "sudo lxc exec winlure -- bash -c 'python3 -m venv /opt/winlure/venv && /opt/winlure/venv/bin/pip install -q paramiko scapy impacket pyyaml flask pyopenssl cryptography dnspython ldap3 pycryptodomex 2>&1 | tail -1'", timeout=180):
        return False
    print(f"  Python deps installed")

    # Step 6: CRITICAL — Move SSH to 2222 BEFORE winlure (exact VM 200)
    if not ssh_vm(ip, "sudo lxc exec winlure -- sed -i 's/^.*Port 22$/Port 2222/' /etc/ssh/sshd_config"):
        return False
    if not ssh_vm(ip, "sudo lxc exec winlure -- systemctl restart sshd"):
        return False
    print(f"  SSH moved to 2222")

    # Step 7: Sysctl (ignore container errors, exact VM 200)
    ssh_vm(ip, "sudo lxc exec winlure -- sysctl -p /etc/sysctl.d/99-winlure.conf 2>/dev/null", check=False)
    print(f"  Sysctl applied")

    # Step 8: Add macvlan with public IP (exact VM 200)
    if not ssh_vm(ip, "sudo lxc config device add winlure eth1 nic nictype=macvlan parent=eth0"):
        return False
    time.sleep(3)
    if not ssh_vm(ip, f"sudo lxc exec winlure -- ip link set eth1 up"):
        return False
    if not ssh_vm(ip, f"sudo lxc exec winlure -- ip addr add {pub}/{PUB_MASK} dev eth1"):
        return False
    ssh_vm(ip, f"sudo lxc exec winlure -- ip route add default via {PUB_GW} dev eth1 metric 50 2>/dev/null", check=False)
    # Persist
    ssh_vm(ip, f"""sudo lxc exec winlure -- bash -c 'mkdir -p /etc/networkd-dispatcher/routable.d && cat > /etc/networkd-dispatcher/routable.d/50-pub-ip.sh << "EOFI"
#!/bin/bash
ip link set eth1 up 2>/dev/null || true
ip addr add {pub}/{PUB_MASK} dev eth1 2>/dev/null || true
ip route add default via {PUB_GW} dev eth1 metric 50 2>/dev/null || true
EOFI
chmod +x /etc/networkd-dispatcher/routable.d/50-pub-ip.sh'""", check=False)
    print(f"  Public IP {pub}/{PUB_MASK} on eth1")

    # Step 9: Configure winlure service — bind to eth1 public IP (exact VM 200)
    if not ssh_vm(ip, f"sudo lxc exec winlure -- sed -i 's|--interface .* --ip [0-9.]*|--interface eth1 --ip {pub}|' /etc/systemd/system/winlure.service"):
        return False

    # Step 10: Persona (exact VM 200)
    P = "/opt/winlure/winlure/config/personas/win2022_dc.yaml"
    ssh_vm(ip, f"sudo lxc exec winlure -- sed -i 's/hostname: .*/hostname: {hostname}/' {P}")
    ssh_vm(ip, f"sudo lxc exec winlure -- sed -i 's/netbios_name: .*/netbios_name: {hostname}/' {P}")
    ssh_vm(ip, f"sudo lxc exec winlure -- sed -i 's/domain: .*/domain: {domain}/' {P}")
    ssh_vm(ip, f"sudo lxc exec winlure -- sed -i 's/workgroup: .*/workgroup: {workgroup}/' {P}")
    ssh_vm(ip, f"sudo lxc exec winlure -- sed -i 's/target_name: .*/target_name: {hostname}/' {P}")
    ssh_vm(ip, f"sudo lxc exec winlure -- sed -i 's|ip_address: .*|ip_address: {pub}|' {P}")
    print(f"  Persona: {hostname}.{domain}")

    # Step 11: Watchlist pusher config (exact VM 200)
    ssh_vm(ip, "sudo lxc exec winlure -- sed -i 's|AIO_HOST = .*|AIO_HOST = \\\"172.16.3.113\\\"|' /opt/trap/watchlist_pusher.py")
    ssh_vm(ip, "sudo lxc exec winlure -- sed -i 's/AIO_PORT = .*/AIO_PORT = 2222/' /opt/trap/watchlist_pusher.py")
    ssh_vm(ip, f"sudo lxc exec winlure -- sed -i 's|216.126.0.201.*self public|{pub}\\\",   # self IP|' /opt/trap/watchlist_pusher.py")
    ssh_vm(ip, f"sudo lxc exec winlure -- sed -i '/IGNORE_IPS = {{/a\\    \\\"{PUB_GW}\\\",    # gateway' /opt/trap/watchlist_pusher.py")

    # Step 12: AIO route from container (exact VM 200)
    ssh_vm(ip, "sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1")
    ssh_vm(ip, "sudo iptables -t nat -C POSTROUTING -s 10.0.0.0/8 -d 172.16.3.0/24 -j MASQUERADE 2>/dev/null || sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -d 172.16.3.0/24 -j MASQUERADE")
    # Get LXD bridge gateway
    lxd_gw_cmd = subprocess.run(
        f"ssh -i {KEY} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null colo8gent@{ip} \"echo 'CHANGE_ME' | sudo -S true 2>/dev/null && sudo lxc network get lxdbr0 ipv4.address\"",
        shell=True, capture_output=True, text=True, timeout=15
    )
    lxd_gw = lxd_gw_cmd.stdout.strip().split("/")[0] if lxd_gw_cmd.returncode == 0 else "10.12.98.1"
    ssh_vm(ip, f"sudo lxc exec winlure -- ip route add 172.16.3.0/24 via {lxd_gw} dev eth0 2>/dev/null || true", check=False)
    ssh_vm(ip, "echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-forward.conf > /dev/null")
    print(f"  AIO route via {lxd_gw}")

    # Step 13: WSL key for watchlist pusher (exact VM 200)
    ssh_vm(ip, "sudo lxc exec winlure -- mkdir -p /root/.ssh")
    ssh_vm(ip, "sudo lxc exec winlure -- chmod 700 /root/.ssh")
    ssh_vm(ip, "sudo lxc file push /tmp/wsl_key winlure/root/.ssh/id_ed25519")
    ssh_vm(ip, "sudo lxc exec winlure -- chmod 600 /root/.ssh/id_ed25519")
    print(f"  WSL key for pusher")

    # Step 14: Set container hostname
    ssh_vm(ip, f"sudo lxc exec winlure -- hostnamectl set-hostname {hostname.lower()}", check=False)
    print(f"  Container hostname: {hostname.lower()}")

    # Step 15: Start services (exact VM 200)
    ssh_vm(ip, "sudo lxc exec winlure -- systemctl daemon-reload")
    ssh_vm(ip, "sudo lxc exec winlure -- systemctl enable winlure trap-honeypot watchlist-pusher")
    ssh_vm(ip, "sudo lxc exec winlure -- systemctl start trap-honeypot")
    ssh_vm(ip, "sudo lxc exec winlure -- systemctl start watchlist-pusher")
    ssh_vm(ip, "sudo lxc exec winlure -- systemctl start winlure")
    time.sleep(3)
    print(f"  Services started")

    # Step 15: Verify (exact VM 200)
    r = subprocess.run(
        f"ssh -i {KEY} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null colo8gent@{ip} \"echo 'CHANGE_ME' | sudo -S true 2>/dev/null && "
        f"echo === STATUS === && "
        f"sudo lxc exec winlure -- systemctl is-active winlure && "
        f"sudo lxc exec winlure -- systemctl is-active trap-honeypot && "
        f"sudo lxc exec winlure -- systemctl is-active watchlist-pusher && "
        f"echo === LISTENERS === && "
        f"sudo lxc exec winlure -- bash -c 'echo TCP: \\$(ss -tln | grep -c LISTEN); echo UDP: \\$(ss -uln | grep -c UNCONN)' && "
        f"echo === TEST === && "
        f"echo QUIT | sudo lxc exec winlure -- timeout 3 nc -q1 127.0.0.1 21 2>/dev/null && "
        f"echo === HOST SSH === && hostname\"",
        shell=True, capture_output=True, text=True, timeout=30
    )
    print(r.stdout)
    if "active" in r.stdout and "this is a trap" in r.stdout:
        print(f"  RESULT: SUCCESS")
        return True
    else:
        print(f"  RESULT: PARTIAL — check logs")
        return False


def main():
    parser = argparse.ArgumentParser(description="Deploy Win-Lure VMs with LXC")
    parser.add_argument("--start", type=int, default=0, help="Start index (0-9)")
    parser.add_argument("--count", type=int, default=10, help="Number of VMs")
    args = parser.parse_args()

    vms = VMS[args.start:args.start + args.count]
    print(f"Deploying {len(vms)} VMs: {[v['vmid'] for v in vms]}\n")

    pack_source()

    results = {}
    for vm in vms:
        try:
            if not create_vm(vm):
                results[vm["vmid"]] = False
                continue
            results[vm["vmid"]] = deploy_in_vm(vm)
        except Exception as e:
            print(f"  EXCEPTION: {e}")
            results[vm["vmid"]] = False

    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    for vm in vms:
        ok = results.get(vm["vmid"], False)
        print(f"  VM {vm['vmid']} {vm['name']:15s} {vm['mgmt_ip']:15s} {vm['pub_ip']:18s} {'OK' if ok else 'FAIL'}")
    ok_count = sum(1 for v in results.values() if v)
    print(f"\n{ok_count}/{len(vms)} deployed successfully.")


if __name__ == "__main__":
    main()
