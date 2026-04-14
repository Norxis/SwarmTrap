# Win-Lure + Trap Honeypot — LXC Deployment Guide

## Overview

Three-service honeypot stack running in a Proxmox LXC container:

- **Win-Lure** — AF_PACKET-based Windows persona emulator (SMB, RDP, MSSQL, SSH, IIS, WinRM, NetBIOS, MSRPC)
- **trap_honeypot.py** — Multi-protocol socket honeypot covering 45 TCP + 15 UDP services, all responding "this is a trap"
- **watchlist_pusher.py** — Tails both logs, auto-pushes attacker IPs to AIO watchlist (priority 1, capture_depth 2)

Combined: **69 honeypot services** per container, with automatic watchlist integration.

## Base Template

| Property | Value |
|----------|-------|
| Source | CT110 on PV1 (192.168.0.100) |
| Snapshot | `winlure_trap_base_v2` (2026-03-16) |
| OS | Ubuntu 22.04 LTS (jammy) |
| Python | 3.10.12 |
| Disk | 8 GB (1.6 GB used) |
| Default | 2 cores, 4 GB RAM, 512 MB swap |

## Quick Deploy

```bash
# From WSL2
python3 ~/DFI2/winlure/deploy_winlure_lxc.py \
    --ctid 130 \
    --hostname FINANCE-DC01 \
    --lan-ip 172.16.3.130 \
    --pub-ip 216.126.0.202/32 \
    --domain FINANCE.LOCAL \
    --workgroup FINANCE
```

### Required Arguments

| Arg | Description | Example |
|-----|-------------|---------|
| `--ctid` | New container ID | `130` |
| `--hostname` | NetBIOS name (max 15 chars, auto-uppercased) | `FINANCE-DC01` |
| `--lan-ip` | LAN IP on v172 bridge | `172.16.3.130` |
| `--pub-ip` | Public IP with mask | `216.126.0.202/32` |

### Optional Arguments

| Arg | Default | Description |
|-----|---------|-------------|
| `--domain` | `CORP.LOCAL` | AD domain for persona |
| `--workgroup` | `CORP` | NetBIOS workgroup |
| `--cores` | `2` | CPU cores |
| `--memory` | `4096` | RAM in MB |
| `--no-onboot` | (on by default) | Don't start on boot |
| `--dry-run` | | Print plan without executing |

## What the Script Does

1. **Clone** CT110 `winlure_trap_base_v2` snapshot → new CTID (full clone)
2. **Configure** hostname, cores, memory, onboot
3. **Set networking** — LAN IP on v172 bridge with gateway 172.16.3.1
4. **Start** container, wait for boot
5. **Update persona** — hostname, netbios_name, domain, workgroup, target_name, dns_aliases in `win2022_dc.yaml`
6. **Add public IP** — as /32 secondary on eth0 + persistence script
7. **Update winlure service** — set `--ip` to public IP
8. **Update watchlist pusher** — set self-IP ignore list (LAN + public)
9. **Restart** all 3 services and verify

## Service Architecture

### Win-Lure (AF_PACKET raw sockets)

Emulates a Windows Server 2022 Domain Controller. Fools Nmap OS detection, SMB/RDP/MSSQL scripts, p0f, impacket, and brute-forcers.

| TCP Port | Service | TCP Port | Service |
|----------|---------|----------|---------|
| 22 | SSH (OpenSSH for Windows) | 445 | SMB |
| 80 | IIS 10.0 | 1433 | MSSQL 2022 |
| 135 | MSRPC EPM | 3389 | RDP |
| 139 | NetBIOS Session | 5985 | WinRM |

| UDP Port | Service |
|----------|---------|
| 137 | NBNS |
| 1434 | SQL Browser |

**Note:** DNS (53) removed from win-lure — handled by trap_honeypot instead so it responds "this is a trap".

### trap_honeypot.py (standard sockets)

All services respond "this is a trap" in protocol-appropriate format.

#### TCP (45 ports)

| Port | Service | Port | Service | Port | Service |
|------|---------|------|---------|------|---------|
| 21 | FTP | 2049 | NFS | 6379 | Redis |
| 23 | Telnet | 2181 | ZooKeeper | 6443 | K8s API |
| 25 | SMTP | 2375 | Docker API | 6667 | IRC |
| 53 | DNS | 2379 | etcd | 8080 | HTTP-Alt |
| 110 | POP3 | 3000 | Grafana | 8088 | Hadoop YARN |
| 143 | IMAP | 3128 | Squid Proxy | 8443 | HTTPS-Alt |
| 443 | HTTPS | 3306 | MySQL | 8500 | Consul |
| 554 | RTSP | 5060 | SIP | 8888 | Jenkins |
| 631 | CUPS/IPP | 5222 | XMPP | 9042 | Cassandra |
| 636 | LDAPS | 5432 | PostgreSQL | 9090 | Prometheus |
| 873 | Rsync | 5555 | ADB | 9092 | Kafka |
| 993 | IMAPS | 5672 | AMQP | 9200 | Elasticsearch |
| 995 | POP3S | 5900 | VNC | 10250 | Kubelet |
| 1080 | SOCKS | 5984 | CouchDB | 11211 | Memcached |
| 1723 | PPTP | | | 27017 | MongoDB |
| 1883 | MQTT | | | | |

#### UDP (15 ports)

| Port | Service | Port | Service |
|------|---------|------|---------|
| 53 | DNS (TXT: "this is a trap") | 1812 | RADIUS |
| 69 | TFTP | 3478 | STUN |
| 123 | NTP (ref ID: "TRAP") | 4500 | NAT-T/IPSec |
| 161 | SNMP (logs community string) | 5060 | SIP |
| 500 | IKE/IPSec | 5353 | mDNS |
| 514 | Syslog (capture only) | 5683 | CoAP |
| 1194 | OpenVPN | 51820 | WireGuard |
| 1701 | L2TP | | |

## File Layout Inside Container

```
/opt/winlure/
    venv/                              # Python venv (paramiko, scapy, impacket, etc.)
    winlure/
        winlure.py                     # Main entry point
        core/bridge.py                 # AF_PACKET engine
        core/personality.py            # TCP/IP fingerprint
        core/tcp_state.py              # TCP state machine
        core/evidence.py               # Evidence logging
        config/persona.py              # YAML loader
        config/personas/win2022_dc.yaml  # *** PERSONA CONFIG — edit this ***
        services/smb.py, rdp.py, ssh_win.py, http_iis.py, mssql.py,
                 winrm.py, dns_server.py, netbios.py, ldap_ad.py, stubs.py
        traffic/background.py          # Background traffic gen
    state/                             # Runtime state (creds DB, keys)
    winlure.log

/opt/trap/
    trap_honeypot.py                   # Multi-protocol honeypot
    trap.log
    watchlist_pusher.py                # Attacker IP → AIO watchlist
    watchlist_pusher.log
    pushed_ips.db                      # Local dedup (SQLite, auto-created)

/etc/systemd/system/
    winlure.service                    # Win-Lure systemd unit
    trap-honeypot.service              # Trap honeypot systemd unit
    watchlist-pusher.service           # Watchlist pusher systemd unit

/etc/sysctl.d/99-winlure.conf         # TTL=128, tcp_timestamps=0 (Windows fingerprint)
/etc/rsyslog.d/99-dfi-forward.conf     # Syslog → 172.16.3.2:514 (PV1 evidence pipeline)
/etc/networkd-dispatcher/routable.d/50-pub-ip.sh  # Persistent public IP
```

## Persona Configuration

Edit `/opt/winlure/winlure/config/personas/win2022_dc.yaml`:

```yaml
persona:
  identity:
    hostname: FINANCE-DC01           # NetBIOS name (≤15 chars)
    domain: FINANCE.LOCAL            # AD domain
    netbios_name: FINANCE-DC01
    workgroup: FINANCE
  network:
    ip_address: 172.16.3.130         # LAN IP
  users:
    - username: Administrator
      password: "P@ssw0rd!Corp2022"  # Fake creds (captured in NTLM hashes)
      # ... add/modify users as needed
```

After editing: `systemctl restart winlure`

## Operations

### Check status
```bash
# From PV1
pct exec <CTID> -- systemctl status winlure
pct exec <CTID> -- systemctl status trap-honeypot
pct exec <CTID> -- systemctl status watchlist-pusher
pct exec <CTID> -- ss -tlnp | wc -l    # TCP listener count
pct exec <CTID> -- ss -ulnp | wc -l    # UDP listener count
```

### View logs
```bash
pct exec <CTID> -- tail -50 /opt/winlure/winlure.log          # Win-Lure
pct exec <CTID> -- tail -50 /opt/trap/trap.log                 # Trap honeypot
pct exec <CTID> -- tail -50 /opt/trap/watchlist_pusher.log     # Watchlist pusher
```

### Check watchlist pushes
```bash
# From AIO
sudo sqlite3 /opt/dfi-hunter/watchlist.db "SELECT * FROM watchlist WHERE source='honeypot' ORDER BY updated_at DESC LIMIT 20"
```

### Restart services
```bash
pct exec <CTID> -- systemctl restart winlure
pct exec <CTID> -- systemctl restart trap-honeypot
pct exec <CTID> -- systemctl restart watchlist-pusher
```

### Test from external
```bash
nmap -sV -O <PUBLIC_IP>                    # Should detect "Windows Server 2022"
curl http://<PUBLIC_IP>:9200               # Should return {"tagline": "this is a trap"}
echo QUIT | nc <PUBLIC_IP> 21              # Should return "220 this is a trap"
dig @<PUBLIC_IP> anything.test TXT         # Should return "this is a trap"
```

### Snapshot management
```bash
# List snapshots
pct listsnapshot <CTID>
# Create new snapshot
pct snapshot <CTID> <name> --description "description"
# Rollback
pct rollback <CTID> <name>
```

## Batch Deploy Example

```bash
# Deploy a fleet of honeypots
for i in 130 131 132; do
    python3 ~/DFI2/winlure/deploy_winlure_lxc.py \
        --ctid $i \
        --hostname "TRAP-$(printf '%03d' $i)" \
        --lan-ip "172.16.3.$i" \
        --pub-ip "216.126.0.$((i+70))/32" \
        --domain "CORP.LOCAL"
done
```

## CRITICAL — Bare-Metal / VM Deploy (non-LXC)

When deploying winlure to a real host (not Proxmox LXC), you **MUST**:

1. **Move SSH to port 2222 BEFORE deploying** — winlure AF_PACKET bridge captures ALL port 22 traffic, killing management SSH
2. **Use a SEPARATE interface** for honeypot — never bind winlure to the management NIC
3. **Verify SSH on 2222 works** before starting winlure

```bash
# MANDATORY before winlure deploy on bare-metal/VM
sudo sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config
sudo systemctl restart sshd
# TEST: ssh -p 2222 user@host
# ONLY THEN start winlure
```

Failure to do this **will lock you out of the host** — requires physical/IPMI console recovery.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Win-Lure not capturing | Check `--ip` in winlure.service matches public IP |
| Trap port conflict | Check `ss -tlnp` for port overlap with win-lure |
| No public IP after reboot | Check `/etc/networkd-dispatcher/routable.d/50-pub-ip.sh` exists and is executable |
| Services not starting | `journalctl -u winlure -n 50` / `tail -50 /opt/trap/trap.log` |
| Python import error | winlure.service needs `PYTHONPATH=/opt/winlure`, `WorkingDirectory=/opt/winlure` |
| Nmap doesn't detect Windows | Verify `/etc/sysctl.d/99-winlure.conf` has `ip_default_ttl=128` |
| Watchlist not pushing | Check `tail -20 /opt/trap/watchlist_pusher.log` — SSH to AIO at 172.16.3.113:2222 |
| Self-IP in watchlist | Public IP in IGNORE_IPS; RFC1918 auto-ignored globally |
| Pusher paramiko error | Service must use `/opt/winlure/venv/bin/python3`, not system python |

## Watchlist Pipeline

```
attacker → Win-Lure/Trap (logs connection)
    ↓
watchlist_pusher.py (every 60s)
    ↓ tails trap.log + winlure.log
    ↓ extracts source IPs, filters RFC1918/self
    ↓ deduplicates (re-push only after 1 hour)
    ↓ SSH → AIO 172.16.3.113:2222
    ↓
AIO watchlist.db (priority=1, capture_depth=2, source='honeypot')
    ↓
update_recon_addresslist.py (hourly cron on AIO)
    ↓ queries watchlist WHERE source IN ('evidence_ingest','honeypot')
    ↓ diff-based sync (add new, remove stale)
    ↓
MikroTik CCR2116 recon address-list
    ↓
AIO capture engine → increased packet capture for attacker IP
```

- **Priority 1** — highest (honeypot = confirmed attacker)
- **Capture depth 2** — full payload capture
- **TTL 30 days** — auto-expires, refreshed on repeat visits
- **Source tag** — `honeypot:<hostname>:<services>` (e.g. `honeypot:this-is-a-trap:FTP,SMTP`)
- **Dedup** — local SQLite (`pushed_ips.db`) prevents re-pushing same IP within 1 hour
- **Self-IP ignore** — all RFC1918 (192.168.*, 172.16.3.*, 10.*), link-local (169.254.*), public self-IP auto-excluded
- **MikroTik sync** — `update_recon_addresslist.py` runs hourly on AIO, adds honeypot IPs to MikroTik `recon` address-list
- **Threat intel feeds** — REMOVED from watchlist (140K IPs deleted, cron disabled 2026-03-16)

### AIO Watchlist Sources (active)

| Source | Count | Description |
|--------|-------|-------------|
| xgb_scorer | ~30K | XGBoost ML classifier |
| classifier | ~16K | CNN/inline classifier |
| session_rules | ~5K | Session rule engine (PV1 cron) |
| evidence_ingest | ~550 | Windows event evidence |
| rule | ~230 | Manual/static rules |
| honeypot | growing | Win-Lure + Trap honeypot IPs |
| winhunt | ~7 | WinHunt agent detections |

## Resource Usage

Per container (idle): ~35 MB RAM, <1% CPU. Under scan: ~100 MB RAM, 2-5% CPU per core.

Safe to run 20+ containers on PV1 (472 GB RAM, 80 CPUs).
