from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _fix_path(p: str) -> str:
    """Normalize Windows path — replace backslash with forward slash.

    This is a safety net against the '\\\\' double-backslash mistake.
    When paths pass through Python/bash/JSON layers, sequences like
    \\n, \\t, \\r, \\a get silently interpreted as escape characters,
    corrupting paths like 'C:\\\\new_folder' → 'C:\\new_folder' (newline).
    Forward slashes work everywhere on Windows and avoid this entirely.
    """
    return p.replace("\\", "/")


@dataclass
class PcapConfig:
    enabled: bool = True
    interface: str = "Ethernet"
    snap_len: int = 256
    buffer_mb: int = 16
    bpf_filter: str = ""
    flow_timeout_s: int = 120
    flow_drain_rst_s: int = 2
    flow_drain_fin_s: int = 5
    max_active_flows: int = 50000
    max_event_pkts: int = 128
    max_flow_pkts: int = 10000
    capture_source: int = 1
    capture_mode: str = "auto"  # "auto" | "npcap" | "raw_socket"
    local_networks: list[str] = field(default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])


@dataclass
class EvidenceConfig:
    enabled: bool = True
    channels: list[str] = field(
        default_factory=lambda: [
            "Security",
            "System",
            "Application",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
            "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
            "Microsoft-Windows-WinRM/Operational",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft-Windows-Sysmon/Operational",
        ]
    )
    iis_log_dir: str = r"C:\inetpub\logs\LogFiles\W3SVC1"
    logon_map_ttl_hours: int = 24
    suspicious_patterns: list[str] = field(
        default_factory=lambda: [
            r"(cmd|powershell|pwsh).*(/c|/k|-enc|-e\s)",
            r"(nc|ncat|netcat)\s.*(-e|-c)",
            r"(wget|curl|invoke-webrequest|iwr)\s",
            r"(certutil)\s.*(-urlcache|-decode)",
            r"(bitsadmin)\s.*/transfer",
            r"(chmod|bash|/bin/sh)",
            r"(whoami|net\s+(user|localgroup|group))",
            r"(reg\s+(add|delete|query).*run)",
            r"(schtasks\s*/create)",
            r"(wmic\s+process\s+call\s+create)",
            r"(mshta|regsvr32|rundll32)\s",
            r"(python|perl|ruby)\s.*(-c|-e)",
            r"base64",
            r"(reverse|bind)\s*shell",
            r"(mimikatz|lazagne|procdump)",
        ]
    )
    download_patterns: list[str] = field(
        default_factory=lambda: [
            r"(certutil)\s.*-urlcache",
            r"(bitsadmin)\s.*/transfer",
            r"(wget|curl|invoke-webrequest|iwr)\s+https?://",
            r"(powershell|pwsh).*downloadfile",
            r"(powershell|pwsh).*downloadstring",
            r"(start-bitstransfer)",
        ]
    )


@dataclass
class ServiceDef:
    name: str
    ports: list[int]
    enabled: bool = True


@dataclass
class ExporterConfig:
    enabled: bool = True
    staging_dir: str = r"C:\Program Files\DFI\staging"
    export_interval_s: int = 30
    max_rows_per_file: int = 10000
    file_prefix: str = "dfi"
    retention_hours: int = 720  # 30 days
    clickhouse_url: str = ""  # e.g. "http://192.168.0.100:8123" — empty = disabled
    clickhouse_db: str = "dfi"


@dataclass
class EyeConfig:
    process_monitor: bool = True
    process_monitor_interval_s: int = 5
    socket_monitor: bool = True
    socket_monitor_interval_s: int = 10
    dns_monitor: bool = True
    file_integrity: bool = True
    file_integrity_interval_s: int = 60
    file_integrity_paths: list[str] = field(default_factory=lambda: [
        r"C:\inetpub\wwwroot",
        r"C:\Windows\System32\drivers\etc",
        r"C:\Users\Administrator\.ssh",
        r"C:\ProgramData\ssh",
        r"C:\Windows\Tasks",
    ])
    shell_profiler: bool = True
    honeypot_detection: bool = True
    breadcrumb_tracking: bool = True
    memory_forensics: bool = True


@dataclass
class HandConfig:
    enabled: bool = True
    max_queue_size: int = 256
    default_timeout: int = 30
    action_log_path: str = r"C:\Program Files\DFI\logs\command_log.jsonl"
    rate_limit_per_sec: float = 10.0
    rate_limit_burst: int = 50


@dataclass
class CommConfig:
    heartbeat_interval_s: int = 60
    batch_idle_s: int = 30
    batch_active_s: int = 5
    priority_immediate: bool = True


@dataclass
class ModelConfig:
    xgboost_enabled: bool = True
    model_path: str = r"C:\Program Files\DFI\models\xgb_model.json"
    freq_table_path: str = r"C:\Program Files\DFI\models\freq_table.json"
    inference_at_packets: list[int] = field(default_factory=lambda: [5, 20, 50])
    min_confidence_accept: float = 0.90
    min_confidence_tentative: float = 0.70


@dataclass
class StandaloneConfig:
    labeler_enabled: bool = True
    alert_enabled: bool = True
    alert_threshold: float = 0.85
    alert_channels: list[dict] = field(default_factory=lambda: [
        {"type": "log", "path": r"C:\Program Files\DFI\logs\alerts.jsonl"},
    ])
    dataset_export_enabled: bool = False
    dataset_export_dir: str = r"C:\Program Files\DFI\dataset"
    dataset_export_format: str = "csv"


@dataclass
class AgentConfig:
    vm_id: str = "win-honey-01"
    mgmt_nic_ip: str = "0.0.0.0"
    agent_port: int = 9200
    token: str = ""
    buffer_path: str = r"C:\Program Files\DFI\data\agent_buffer.db"
    log_dir: str = r"C:\Program Files\DFI\logs"
    log_level: str = "INFO"
    retention_days: int = 7
    pcap: PcapConfig = field(default_factory=PcapConfig)
    evidence: EvidenceConfig = field(default_factory=EvidenceConfig)
    exporter: ExporterConfig = field(default_factory=ExporterConfig)
    eyes: EyeConfig = field(default_factory=EyeConfig)
    hand: HandConfig = field(default_factory=HandConfig)
    comm: CommConfig = field(default_factory=CommConfig)
    inference: ModelConfig = field(default_factory=ModelConfig)
    standalone: StandaloneConfig = field(default_factory=StandaloneConfig)
    services: list[ServiceDef] = field(
        default_factory=lambda: [
            ServiceDef("rdp", [3389], True),
            ServiceDef("smb", [445], True),
            ServiceDef("winrm", [5985, 5986], True),
            ServiceDef("mssql", [1433], True),
            ServiceDef("iis_http", [80], True),
            ServiceDef("iis_https", [443], True),
        ]
    )
    _local_ips_cache: set[str] = field(default_factory=lambda: {"127.0.0.1"}, init=False, repr=False)
    _local_ips_cache_ts: float = field(default=0.0, init=False, repr=False)
    _suspicious_re: list[re.Pattern] = field(default_factory=list, init=False, repr=False)
    _download_re: list[re.Pattern] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        # Normalize ALL path fields — safety net against \\ escape corruption
        self.buffer_path = _fix_path(self.buffer_path)
        self.log_dir = _fix_path(self.log_dir)
        self.exporter.staging_dir = _fix_path(self.exporter.staging_dir)
        self.evidence.iis_log_dir = _fix_path(self.evidence.iis_log_dir)
        self.hand.action_log_path = _fix_path(self.hand.action_log_path)
        self.inference.model_path = _fix_path(self.inference.model_path)
        self.inference.freq_table_path = _fix_path(self.inference.freq_table_path)
        self.standalone.dataset_export_dir = _fix_path(self.standalone.dataset_export_dir)
        self.eyes.file_integrity_paths = [_fix_path(p) for p in self.eyes.file_integrity_paths]
        for ch in self.standalone.alert_channels:
            if "path" in ch:
                ch["path"] = _fix_path(ch["path"])
        self._suspicious_re = [re.compile(p, re.IGNORECASE) for p in self.evidence.suspicious_patterns]
        self._download_re = [re.compile(p, re.IGNORECASE) for p in self.evidence.download_patterns]

    @classmethod
    def from_json(cls, path: str | Path) -> "AgentConfig":
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)

        pcap = PcapConfig(**{k: v for k, v in data.get("pcap", {}).items() if k in PcapConfig.__dataclass_fields__})
        evidence_raw = data.get("evidence", {})
        evidence = EvidenceConfig(**{k: v for k, v in evidence_raw.items() if k in EvidenceConfig.__dataclass_fields__})
        exporter = ExporterConfig(**{k: v for k, v in data.get("exporter", {}).items() if k in ExporterConfig.__dataclass_fields__})
        eyes = EyeConfig(**{k: v for k, v in data.get("eyes", {}).items() if k in EyeConfig.__dataclass_fields__})
        hand = HandConfig(**{k: v for k, v in data.get("hand", {}).items() if k in HandConfig.__dataclass_fields__})
        comm = CommConfig(**{k: v for k, v in data.get("comm", {}).items() if k in CommConfig.__dataclass_fields__})
        inference = ModelConfig(**{k: v for k, v in data.get("inference", {}).items() if k in ModelConfig.__dataclass_fields__})
        standalone = StandaloneConfig(**{k: v for k, v in data.get("standalone", {}).items() if k in StandaloneConfig.__dataclass_fields__})

        services_raw = data.get("services", {})
        services: list[ServiceDef] = []
        if isinstance(services_raw, dict):
            for name, cfg in services_raw.items():
                ports = cfg.get("ports") or ([cfg["port"]] if "port" in cfg else [])
                services.append(ServiceDef(name=name, ports=[int(p) for p in ports], enabled=bool(cfg.get("enabled", True))))
        elif isinstance(services_raw, list):
            for item in services_raw:
                services.append(ServiceDef(name=item["name"], ports=list(item["ports"]), enabled=bool(item.get("enabled", True))))

        out = cls(
            vm_id=data.get("vm_id", "win-honey-01"),
            mgmt_nic_ip=data.get("mgmt_nic_ip", "0.0.0.0"),
            agent_port=int(data.get("agent_port", 9200)),
            token=data.get("token", ""),
            buffer_path=data.get("buffer_path", cls.buffer_path),
            log_dir=data.get("log_dir", cls.log_dir),
            log_level=data.get("log_level", "INFO"),
            retention_days=int(data.get("retention_days", 7)),
            pcap=pcap,
            evidence=evidence,
            exporter=exporter,
            eyes=eyes,
            hand=hand,
            comm=comm,
            inference=inference,
            standalone=standalone,
            services=services or cls().services,
        )
        out.validate()
        return out

    def validate(self) -> None:
        if self.retention_days < 1:
            raise ValueError("retention_days must be >= 1")
        for cidr in self.pcap.local_networks:
            ipaddress.ip_network(cidr)
        if self.pcap.max_event_pkts < 1:
            raise ValueError("pcap.max_event_pkts must be >= 1")
        if self.agent_port < 1 or self.agent_port > 65535:
            raise ValueError("agent_port must be 1-65535")

    def honeypot_ports(self) -> set[int]:
        ports: set[int] = set()
        for svc in self.services:
            if svc.enabled:
                ports.update(svc.ports)
        return ports

    def port_to_service(self) -> dict[int, str]:
        mapping: dict[int, str] = {}
        for svc in self.services:
            if svc.enabled:
                for p in svc.ports:
                    mapping[p] = svc.name
        return mapping

    @property
    def local_ips(self) -> set[str]:
        now = time.time()
        if now - self._local_ips_cache_ts < 60 and self._local_ips_cache:
            return set(self._local_ips_cache)
        ips: set[str] = {"127.0.0.1"}
        if self.mgmt_nic_ip and self.mgmt_nic_ip != "0.0.0.0":
            ips.add(self.mgmt_nic_ip)
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                ips.add(info[4][0])
        except Exception:
            pass
        self._local_ips_cache = ips
        self._local_ips_cache_ts = now
        return set(self._local_ips_cache)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vm_id": self.vm_id,
            "mgmt_nic_ip": self.mgmt_nic_ip,
            "agent_port": self.agent_port,
            "token": self.token,
            "buffer_path": self.buffer_path,
            "log_dir": self.log_dir,
            "log_level": self.log_level,
            "retention_days": self.retention_days,
            "pcap": {k: v for k, v in self.pcap.__dict__.items()},
            "evidence": {k: v for k, v in self.evidence.__dict__.items()},
            "exporter": {k: v for k, v in self.exporter.__dict__.items()},
            "eyes": {k: v for k, v in self.eyes.__dict__.items()},
            "hand": {k: v for k, v in self.hand.__dict__.items()},
            "comm": {k: v for k, v in self.comm.__dict__.items()},
            "inference": {k: v for k, v in self.inference.__dict__.items()},
            "standalone": {k: v for k, v in self.standalone.__dict__.items()},
            "services": [{"name": s.name, "ports": s.ports, "enabled": s.enabled} for s in self.services],
        }
