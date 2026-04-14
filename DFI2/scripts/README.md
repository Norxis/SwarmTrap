# Scripts

Operational utilities for managing the honeypot infrastructure. These scripts handle container health checks, daily VM resets, data migration, and network-level blocking via MikroTik routers.

## Key Files

### `audit_ct_honeypots.py`

Self-healing health checker for LXC honeypot containers. Runs on the Proxmox host via cron every 5 minutes.

**Containers audited:** CT110 (base honeypot) + CT127-162 (honeypot farm) = 37 containers.

**Checks per container:**
1. Winlure process is running (`pgrep -f winlure.winlure`).
2. `dfi-trap` systemd service is active.
3. `dfi-sensor-agent` systemd service is active.

**Auto-remediation:**
- Dead winlure: Detects the container's IP and persona config, then restarts the process with the correct arguments.
- Dead services: `systemctl restart` on the failed service.

**Performance:** Uses `ThreadPoolExecutor` with 12 workers for parallel container checks. Pre-checks API reachability from the host to skip per-container connectivity probes when the central API is down.

### `daily_reset.py`

Daily honeypot VM rollback and password randomization. Runs on the Proxmox host.

**What it does:**
1. Stops each VM/container.
2. Rolls back to a named snapshot (per-VM overrides or a default baseline).
3. Starts the VM/container.
4. For KVM VMs: waits for the QEMU guest agent, then changes all user passwords to random 32-character strings via `qm guest exec`.

**Inventory:**
- 15 KVM VMs: 10 original honeypots (3 Ubuntu, 4 Windows Server, 1 Windows 10, 3 MSSQL) + 15 honeypot farm VMs.
- 38 LXC containers: CT110, CT112, CT127-162.

**Safety features:**
- 60-second stagger between VMs to avoid thundering herd on storage.
- Dry-run mode (`--dry-run`) and single-VM mode (`--vm 106`).
- Password charset avoids shell-special characters.
- Passwords are intentionally not recorded -- the VM is snapped back to baseline before the next reset.

### `migrate_norm.py`

One-time data migration utility. Moves high-confidence normal (non-attack) flows from the `dfi` database to `dfi_norm` for clean separation of attack and baseline traffic.

**Migration criteria:** Flows with `actor_id = 'norm'` that have an XGBoost prediction of label=0 (clean) with confidence > 0.8.

**Tables migrated per day:**
1. `dfi.flows` -> `dfi_norm.flows`
2. `dfi.labels` -> `dfi_norm.labels` (only label=5 / NORM)
3. `dfi.model_predictions` -> `dfi_norm.model_predictions`
4. `dfi.packets` -> `dfi_norm.packets`

Processes day-by-day to keep memory usage manageable. Uses `max_threads=0` and `max_insert_threads=8` for maximum ClickHouse parallelism.

### `update_recon_addresslist.py`

Syncs watchlist IPs to a MikroTik router's firewall address list for network-level blocking. Runs via cron (hourly).

**CIDR aggregation (3 stages):**
1. **Stage 1:** If >= 5 IPs share a /24, push as a /24 instead of 5 individual /32s.
2. **Stage 2a:** If 4 out of 4 hot /24s fill a /22, promote to /22.
3. **Stage 2b:** If >= 5 hot /24s fill a /20, promote to /20.
4. **Remainder:** Individual /32 entries.

**Diff-based sync:** Maintains local state (JSON file) of what was last pushed. Only adds new entries. Removals are deferred: a stale counter accumulates, and when it reaches 5,000, a bulk wipe-and-reimport is performed. This avoids the O(n) cost of MikroTik's `[find address=x]` for individual removes.

**MikroTik integration:** Uses `.rsc` file import (SFTP upload + `/import`) for batch adds, chunked at 5,000 commands per file. Excludes own subnets and known infrastructure IPs.

## Configuration

Scripts use a mix of constants and environment variables. Key external dependencies:

| Script | Runs On | Schedule | External Systems |
|--------|---------|----------|-----------------|
| `audit_ct_honeypots.py` | Proxmox host | cron 5min | LXC containers via `pct exec` |
| `daily_reset.py` | Proxmox host | cron daily | KVM VMs via `qm`, LXC via `pct` |
| `migrate_norm.py` | ClickHouse host | one-time | Local ClickHouse |
| `update_recon_addresslist.py` | PV1 | cron hourly | MikroTik router via SSH, local SQLite watchlist |

## Dependencies

- `paramiko` -- SSH client for MikroTik communication
- `clickhouse-driver` -- ClickHouse native protocol client (migrate_norm)
- Python standard library (`subprocess`, `sqlite3`, `secrets`, `ipaddress`, `concurrent.futures`)
