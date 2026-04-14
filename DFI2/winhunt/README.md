# WinHunt

Implemented components:
- `dfi_agent/`: Windows capture/evidence/buffer/export package
- `orchestrator/`: MeshCentral pull + ClickHouse ingest daemon
- `meshcentral/`: Proxmox LXC setup scripts
- `install.ps1`: Windows installer for agent service

Quick start:
1. Build config: `python -m dfi_agent --init-config --config config.json`
2. Run agent: `python -m dfi_agent --config config.json`
3. Set secrets: `WINHUNT_MESH_PASSWORD` and optional `WINHUNT_CLICKHOUSE_PASSWORD`
4. Run orchestrator: `python -m orchestrator.main --config orchestrator.json`
