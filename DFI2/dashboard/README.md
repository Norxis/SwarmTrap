# DFI2 Dashboard (Legacy)

**Status: Replaced.** This Streamlit dashboard has been superseded by the React SOC dashboard built into the backend API.

The current dashboard is at `backend_api/ui/soc-dashboard/` and is served at `/ui` on the backend API (port 8010).

---

## What This Was

`dashboard.py` is a Streamlit application that provided 8 pages of operational visibility:

- **Overview** -- total flows, hourly flows, unique attackers, labeled flows
- **VM Status** -- 10-VM grid with Proxmox metrics and per-VM attack flow counts
- **Evidence** -- evidence event types, top attackers by evidence volume, event stream
- **IP Lookup** -- single-IP deep-dive with labels, evidence, group trajectory, movement timeline, and analyst actions (promote/block/watch)
- **Top Attackers** -- top 100 IPs by flow count with port and target cardinality
- **Label Distribution** -- label counts (RECON, KNOCK, BRUTEFORCE, EXPLOIT, COMPROMISE)
- **Ingest Monitor** -- per-minute flow rate chart for the last hour
- **Storage Stats** -- per-table ClickHouse storage (raw, compressed, ratio, rows)

It read directly from ClickHouse and the Proxmox API, and sent analyst actions through the backend API's REST endpoints.

## Why It Was Replaced

The React SPA in `backend_api/ui/soc-dashboard/` provides:
- GOD pipeline health monitoring (4-stage health check)
- Per-service classification (SSH, HTTP, RDP, SQL, SMB)
- Verdict management (DROP/CAPTURE with expiry)
- GeoIP attack maps
- ML training data progress tracking
- Allowlist management
- Faster load times (code-split, no Streamlit server needed)
