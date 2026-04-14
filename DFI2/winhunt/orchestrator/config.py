from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


@dataclass
class MeshConfig:
    url: str = ""
    user: str = ""
    password: str = ""
    device_group: str = "WinHunt-Test"


@dataclass
class ClickHouseConfig:
    host: str = ""
    port: int = 8123
    database: str = "dfi"
    user: str = "default"
    password: str = ""


@dataclass
class OrchestratorConfig:
    mesh: MeshConfig = field(default_factory=MeshConfig)
    clickhouse: ClickHouseConfig = field(default_factory=ClickHouseConfig)
    poll_interval_s: int = 30
    staging_remote_dir: str = r"C:\Program Files\DFI\staging"
    local_download_dir: str = "/opt/winhunt/downloads"
    log_file: str = "/opt/winhunt/orchestrator.log"
    health_interval_s: int = 60

    @classmethod
    def from_json(cls, path: str) -> "OrchestratorConfig":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cfg = cls(
            mesh=MeshConfig(**data.get("mesh", {})),
            clickhouse=ClickHouseConfig(**data.get("clickhouse", {})),
            poll_interval_s=int(data.get("poll_interval_s", 30)),
            staging_remote_dir=data.get("staging_remote_dir", r"C:\Program Files\DFI\staging"),
            local_download_dir=data.get("local_download_dir", "/opt/winhunt/downloads"),
            log_file=data.get("log_file", "/opt/winhunt/orchestrator.log"),
            health_interval_s=int(data.get("health_interval_s", 60)),
        )
        # Environment variable fallback for secrets
        if not cfg.mesh.password:
            cfg.mesh.password = os.environ.get("WINHUNT_MESH_PASSWORD", "")
        if not cfg.clickhouse.password:
            cfg.clickhouse.password = os.environ.get("WINHUNT_CLICKHOUSE_PASSWORD", "")
        if not cfg.mesh.url:
            cfg.mesh.url = os.environ.get("WINHUNT_MESH_URL", "wss://192.168.0.112")
        if not cfg.clickhouse.host:
            cfg.clickhouse.host = os.environ.get("WINHUNT_CLICKHOUSE_HOST", "192.168.0.100")
        # Validate required fields
        if not cfg.mesh.url:
            raise ValueError("mesh.url is required (config or WINHUNT_MESH_URL env)")
        if not cfg.clickhouse.host:
            raise ValueError("clickhouse.host is required (config or WINHUNT_CLICKHOUSE_HOST env)")
        return cfg
