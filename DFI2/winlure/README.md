# Win-Lure Honeypot Deployment

Win-Lure is a Windows persona emulator that makes Linux containers look like real Windows servers to attackers. Combined with a multi-protocol trap honeypot and an automated watchlist pusher, it creates a high-fidelity attacker detection and evidence collection system.

Each deployed instance runs **three services** that together expose **69 honeypot ports** and automatically feed detected attacker IPs into the threat intelligence pipeline.

---

## How It Works

```
attacker scans/probes public IP
        |
        v
+-----------------------------------------------+
|  LXC Container (Ubuntu 22.04)                 |
|                                                |
|  winlure        -- AF_PACKET raw sockets       |
|    Emulates Windows Server 2022 DC             |
|    Ports: 22(SSH), 80(IIS), 135(MSRPC),        |
|           139(NetBIOS), 445(SMB), 1433(MSSQL),  |
|           3389(RDP), 5985(WinRM)                |
|    + UDP 137(NBNS), 1434(SQL Browser)           |
|                                                |
|  trap-honeypot  -- 45 TCP + 15 UDP sockets     |
|    FTP, Telnet, SMTP, DNS, MySQL, PostgreSQL,   |
|    Redis, MongoDB, Elasticsearch, Docker API,   |
|    K8s API, Kafka, Grafana, Jenkins, etc.       |
|    All respond "this is a trap"                 |
|                                                |
|  watchlist-pusher  -- log tailer + SSH client   |
|    Tails winlure.log + trap.log every 60s       |
|    Extracts source IPs, deduplicates locally    |
|    Pushes to watchlist via SSH (priority 1)     |
+-----------------------------------------------+
        |
        v
Watchlist DB (priority=1, depth=2, source='honeypot')
        |
        v
Pipeline: increased capture + edge blocking for attacker IP
```

## Services

### 1. Win-Lure (AF_PACKET raw sockets)

Emulates a Windows Server 2022 Domain Controller at the network layer. Fools Nmap OS detection, SMB/RDP/MSSQL scripts, p0f, impacket, and brute-force tools.

- Configurable persona (hostname, domain, workgroup, DNS aliases)
- TCP: SSH (22), HTTP/IIS (80), MSRPC (135), NetBIOS (139), SMB (445), MSSQL (1433), RDP (3389), WinRM (5985)
- UDP: NBNS (137), SQL Browser (1434)
- Sysctl tuning: TTL=128, tcp_timestamps=0 to match Windows fingerprint

### 2. trap-honeypot (standard sockets)

Covers 45 TCP and 15 UDP ports with protocol-appropriate "this is a trap" responses. Catches attackers scanning for services beyond what Win-Lure emulates (databases, message queues, container APIs, VPNs, etc.).

### 3. watchlist-pusher (log tailer + SSH)

- Tails both `winlure.log` and `trap.log` every 60 seconds
- Extracts unique source IPs from connection logs
- Filters RFC1918, link-local, and self-IP addresses
- Deduplicates with a local SQLite database (re-push only after 1 hour)
- Pushes attacker IPs via SSH to the watchlist database with:
  - `priority=1` (highest -- confirmed attacker contacted a honeypot)
  - `capture_depth=2` (full payload capture)
  - `source='honeypot'`
  - 30-day TTL, refreshed on repeat visits

---

## Deployment Scripts

### `deploy_winlure_lxc.py` -- Proxmox LXC Clone

Clones a pre-built base container (CT110 with snapshot `winlure_trap_base_v2`) to a new CTID on a Proxmox host. Configures networking, persona, public IP, and starts all three services.

```bash
python3 deploy_winlure_lxc.py \
    --ctid 130 \
    --hostname FINANCE-DC01 \
    --lan-ip 172.16.3.130 \
    --pub-ip 216.126.0.202/32 \
    --domain FINANCE.LOCAL \
    --workgroup FINANCE
```

**Steps performed:**
1. Full-clone CT110 snapshot to new CTID
2. Configure hostname, cores (default 2), memory (default 4096 MB)
3. Set LAN networking on bridge
4. Start container
5. Update persona YAML (hostname, domain, workgroup, DNS aliases)
6. Add public IP as /32 secondary on eth0 with persistence script
7. Update winlure service bind IP
8. Update watchlist pusher self-IP ignore list
9. Restart and verify all 3 services

**Arguments:**

| Arg | Required | Default | Description |
|-----|----------|---------|-------------|
| `--ctid` | Yes | -- | New container ID |
| `--hostname` | Yes | -- | NetBIOS name (max 15 chars) |
| `--lan-ip` | Yes | -- | LAN IP (e.g. 172.16.3.130) |
| `--pub-ip` | Yes | -- | Public IP with mask (e.g. 216.126.0.202/32) |
| `--domain` | No | CORP.LOCAL | AD domain name |
| `--workgroup` | No | CORP | NetBIOS workgroup |
| `--cores` | No | 2 | CPU cores |
| `--memory` | No | 4096 | RAM in MB |
| `--dry-run` | No | -- | Print plan without executing |

### `deploy_winlure_vm.py` -- VM Farm Deployment

Creates Ubuntu 24.04 VMs on Proxmox via cloud-init, installs LXD inside each VM, then deploys the Win-Lure stack inside an LXC container within the VM. Designed for deploying fleets of honeypots across separate public IP ranges.

```bash
# Deploy one VM first to test
python3 deploy_winlure_vm.py --start 0 --count 1

# Then deploy the rest
python3 deploy_winlure_vm.py --start 1 --count 9
```

This script handles the full lifecycle: VM creation, cloud-init, LXD setup, tarball extraction, Python deps, SSH port move, macvlan public IP, persona config, watchlist pusher config, AIO routing, and service startup.

The VM definitions are hardcoded in the script with 10 pre-configured personas (EXCHANGE-01, BACKUP-DC01, HR-SQL01, etc.), each with a unique public IP, domain, and workgroup.

---

## Pipeline Integration

```
Attacker -> Win-Lure/Trap (logs connection)
    |
    v
watchlist_pusher.py (every 60s)
    |  tails logs, extracts IPs, filters self/RFC1918
    |  deduplicates (local SQLite, 1-hour window)
    v
Watchlist DB (priority=1, capture_depth=2, source='honeypot', TTL 30d)
    |
    v
Capture engine: increased packet capture for attacker IP
Edge router: address-list sync for NAT redirection
```

Every IP that touches a honeypot is automatically:
1. Added to the watchlist at the highest priority
2. Captured at full depth (D2) by the flow engine
3. Eligible for edge blocking after pipeline analysis

---

## Resource Usage

Per container (idle): ~35 MB RAM, <1% CPU. Under active scanning: ~100 MB RAM, 2-5% CPU per core.

---

## Related

- `WINLURE-DEPLOY.md` -- detailed deployment guide with full port lists, file layouts, troubleshooting, and operational commands
- `backend_api/` -- the SOC dashboard that displays evidence from honeypot detections
