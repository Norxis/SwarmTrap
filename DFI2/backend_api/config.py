import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    ch_host: str = os.environ.get("CH_HOST", "localhost")
    ch_port: int = int(os.environ.get("CH_PORT", "9000"))
    watchlist_db: str = os.environ.get("WATCHLIST_DB", "/opt/dfi-hunter/watchlist.db")
    api_host: str = os.environ.get("BACKEND_API_HOST", "0.0.0.0")
    api_port: int = int(os.environ.get("BACKEND_API_PORT", "8010"))
    active_window_sec: int = int(os.environ.get("ACTIVE_WINDOW_SEC", "900"))
    max_bulk_ips: int = int(os.environ.get("MAX_BULK_IPS", "5000"))
    api_key: str | None = os.environ.get("BACKEND_API_KEY")
    ui_username: str = os.environ.get("BACKEND_UI_USER", "admin")
    ui_password: str | None = os.environ.get("BACKEND_UI_PASS")
    enable_quiet_demoter: bool = os.environ.get("ENABLE_QUIET_DEMOTER", "0") == "1"
    quiet_demote_interval_sec: int = int(os.environ.get("QUIET_DEMOTE_INTERVAL_SEC", "300"))
    quiet_demote_after_sec: int = int(os.environ.get("QUIET_DEMOTE_AFTER_SEC", "3600"))
    pve_host: str = os.environ.get("PVE_HOST", "https://192.168.0.100:8006")
    pve_user: str = os.environ.get("PVE_USER", "root@pam")
    pve_pass: str = os.environ.get("PVE_PASS", "")
    # AIO decommissioned 2026-03-31 — all capture consolidated on PV1
    ml_metrics_dir: str = os.environ.get("ML_METRICS_DIR", "/opt/dfi2/ml_metrics/")
    geoip_path: str = os.environ.get("GEOIP_PATH", "/opt/dfi2/geoip/dbip-city-lite.mmdb")


SETTINGS = Settings()
