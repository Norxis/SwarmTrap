"""WinHunt DFI capture agent entry point.

Threading model per spec (AIO expansion):
  dfi-capture    — Npcap read loop
  dfi-evidence   — ETW subscription + IIS tailing
  dfi-sweep      — Flow timeout check (1s)
  dfi-cleanup    — Data retention (5min)
  dfi-export     — NDJSON file export with priority batching
  dfi-api        — Waitress WSGI (4 threads)
  dfi-heartbeat  — Structured heartbeat (60s)
  dfi-hand       — Command dispatcher queue
  dfi-proc-mon   — Process monitoring (5s poll)
  dfi-sock-mon   — Network socket monitoring (10s poll)
  dfi-file-mon   — File integrity monitoring (60s poll)
  main           — Signal handler, orchestration
"""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
import time
from pathlib import Path

from .buffer import AgentBuffer
from .capture import CaptureThread
from .config import AgentConfig
from .evidence import EvidenceCollector
from .exporter import NdjsonExporter
from .flow_table import FlowTable


def _setup_logging(level: str, log_dir: str) -> None:
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    handlers = [
        logging.StreamHandler(),
        logging.FileHandler(str(log_path / "agent.log"), encoding="utf-8"),
    ]
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
    )


def _write_default_config(path: Path) -> None:
    cfg = AgentConfig()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg.to_dict(), f, indent=2)


def _init_inference_pipeline(cfg, buffer, log):
    """Initialize XGBoost inference pipeline if model exists (Phase 5)."""
    if not cfg.inference.xgboost_enabled:
        log.info("XGBoost inference disabled")
        return None

    model_path = Path(cfg.inference.model_path)
    if not model_path.exists():
        log.info("no XGB model at %s — inference skipped", model_path)
        return None

    try:
        from .inference.engine import XGBEngine
        from .inference.pipeline import InferencePipeline
        from .inference.frequency import FrequencyTable

        engine = XGBEngine(str(model_path))

        freq_path = cfg.inference.freq_table_path
        freq_table = None
        if Path(freq_path).exists():
            freq_table = FrequencyTable(freq_path)

        pipeline = InferencePipeline(engine, cfg, buffer)
        log.info("XGBoost inference pipeline initialized (model=%s)", model_path.name)
        return pipeline
    except Exception as exc:
        log.warning("failed to init inference pipeline: %s", exc)
        return None


def _init_eye_sensors(cfg, buffer, evidence, stop_event, log):
    """Initialize Phase 2 eye sensors. Returns list of started threads."""
    threads = []

    if not cfg.eyes.process_monitor and not cfg.eyes.socket_monitor and not cfg.eyes.file_integrity:
        log.info("all eye sensors disabled")
        return threads

    # Process monitor
    if cfg.eyes.process_monitor:
        try:
            from .eyes.process_monitor import ProcessMonitor
            proc_mon = ProcessMonitor(cfg, buffer, stop_event)
            proc_mon.start()
            threads.append(proc_mon)
            log.info("process monitor started (interval=%ds)", cfg.eyes.process_monitor_interval_s)
        except Exception as exc:
            log.warning("failed to start process monitor: %s", exc)

    # Socket monitor
    if cfg.eyes.socket_monitor:
        try:
            from .eyes.socket_monitor import SocketMonitor
            sock_mon = SocketMonitor(cfg, buffer, stop_event)
            sock_mon.start()
            threads.append(sock_mon)
            log.info("socket monitor started (interval=%ds)", cfg.eyes.socket_monitor_interval_s)
        except Exception as exc:
            log.warning("failed to start socket monitor: %s", exc)

    # File integrity monitor
    if cfg.eyes.file_integrity:
        try:
            from .eyes.file_integrity import FileIntegrityMonitor
            file_mon = FileIntegrityMonitor(cfg, buffer, stop_event)
            file_mon.start()
            threads.append(file_mon)
            log.info("file integrity monitor started (interval=%ds)", cfg.eyes.file_integrity_interval_s)
        except Exception as exc:
            log.warning("failed to start file integrity monitor: %s", exc)

    # Event-driven sensors (not threads — hook into evidence collector)
    if cfg.eyes.dns_monitor:
        try:
            from .eyes.dns_monitor import DnsMonitor
            evidence._dns_monitor = DnsMonitor(cfg, buffer)
            log.info("DNS monitor attached to evidence collector")
        except Exception as exc:
            log.warning("failed to init DNS monitor: %s", exc)

    if cfg.eyes.honeypot_detection:
        try:
            from .eyes.honeypot_detection import HoneypotDetector
            evidence._honeypot_detector = HoneypotDetector(cfg, buffer)
            log.info("honeypot detection attached to evidence collector")
        except Exception as exc:
            log.warning("failed to init honeypot detector: %s", exc)

    if cfg.eyes.shell_profiler:
        try:
            from .eyes.shell_profiler import ShellProfiler
            evidence._shell_profiler = ShellProfiler(cfg, buffer)
            log.info("shell profiler attached to evidence collector")
        except Exception as exc:
            log.warning("failed to init shell profiler: %s", exc)

    return threads


def _init_hand(cfg, buffer, stop_event, log):
    """Initialize Phase 3 command dispatcher. Returns thread or None."""
    if not cfg.hand.enabled:
        log.info("command dispatcher disabled")
        return None

    try:
        from .hand.dispatcher import CommandDispatcher
        dispatcher = CommandDispatcher(cfg, buffer, stop_event)
        dispatcher.start()
        log.info("command dispatcher started (queue_size=%d)", cfg.hand.max_queue_size)
        return dispatcher
    except Exception as exc:
        log.warning("failed to start command dispatcher: %s", exc)
        return None


def _init_heartbeat(cfg, buffer, capture, evidence, flow_table, stop_event, log):
    """Initialize Phase 4 heartbeat thread. Returns thread or None."""
    try:
        from .heartbeat import HeartbeatThread
        hb = HeartbeatThread(cfg, buffer, capture, evidence, flow_table, stop_event)
        hb.start()
        log.info("heartbeat thread started (interval=%ds)",
                 getattr(cfg.comm, 'heartbeat_interval_s', 60))
        return hb
    except Exception as exc:
        log.warning("failed to start heartbeat: %s", exc)
        return None


def _init_labeler_alerting(cfg, buffer, log):
    """Initialize Phase 6 labeler and alerting. Returns (labeler, alert_manager)."""
    labeler = None
    alert_manager = None

    if getattr(cfg.standalone, 'labeler_enabled', False):
        try:
            from .labeler import SessionLabeler
            labeler = SessionLabeler(cfg, buffer)
            log.info("session labeler initialized")
        except Exception as exc:
            log.warning("failed to init labeler: %s", exc)

    if getattr(cfg.standalone, 'alert_enabled', False):
        try:
            from .alerting import AlertManager
            alert_manager = AlertManager(cfg)
            log.info("alert manager initialized")
        except Exception as exc:
            log.warning("failed to init alert manager: %s", exc)

    return labeler, alert_manager


def main() -> None:
    ap = argparse.ArgumentParser(description="WinHunt DFI capture agent")
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--init-config", action="store_true", help="Write default config and exit")
    ap.add_argument("--foreground", action="store_true")
    # Support 'export' subcommand
    ap.add_argument("command", nargs="?", choices=["export"], default=None)
    args, remaining = ap.parse_known_args()

    if args.command == "export":
        from .export import main as export_main
        sys.argv = [sys.argv[0]] + ["export"] + remaining
        export_main()
        return

    cfg_path = Path(args.config)
    if args.init_config:
        _write_default_config(cfg_path)
        print(f"Wrote default config: {cfg_path}")
        return

    cfg = AgentConfig.from_json(cfg_path)
    _setup_logging(cfg.log_level, cfg.log_dir)
    log = logging.getLogger("winhunt.main")

    stop_event = threading.Event()

    # Signal handlers
    def _stop(*_a):
        log.info("shutdown signal received")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _stop)

    # SIGBREAK on Windows
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, _stop)

    # Initialize core components
    buffer = AgentBuffer(cfg.buffer_path, vm_id=cfg.vm_id)

    # Phase 5: Initialize inference pipeline (before flow_table so we can pass it)
    pipeline = _init_inference_pipeline(cfg, buffer, log)

    flow_table = FlowTable(cfg, buffer, pipeline=pipeline)
    capture = CaptureThread(cfg, flow_table, stop_event)
    evidence = EvidenceCollector(cfg, buffer, stop_event)
    exporter = NdjsonExporter(cfg, buffer, stop_event, flow_table=flow_table)

    def sweep_loop() -> None:
        while not stop_event.is_set():
            flow_table.sweep()
            stop_event.wait(1.0)

    def cleanup_loop() -> None:
        while not stop_event.is_set():
            buffer.cleanup(cfg.retention_days)
            stop_event.wait(300)

    sweep_thr = threading.Thread(target=sweep_loop, daemon=True, name="dfi-sweep")
    cleanup_thr = threading.Thread(target=cleanup_loop, daemon=True, name="dfi-cleanup")

    # Start core threads
    capture.start()
    evidence.start()
    exporter.start()
    sweep_thr.start()
    cleanup_thr.start()

    # Phase 2: Eye sensors
    eye_threads = _init_eye_sensors(cfg, buffer, evidence, stop_event, log)

    # Phase 3: Hand command dispatcher
    dispatcher = _init_hand(cfg, buffer, stop_event, log)

    # Phase 4: Heartbeat
    heartbeat = _init_heartbeat(cfg, buffer, capture, evidence, flow_table, stop_event, log)

    # Phase 6: Labeler + alerting
    labeler, alert_manager = _init_labeler_alerting(cfg, buffer, log)

    # Start API server in background thread
    def api_thread():
        from .api import serve_api
        serve_api(cfg, buffer, capture, evidence, flow_table, stop_event,
                  command_dispatcher=dispatcher)

    api_thr = threading.Thread(target=api_thread, daemon=True, name="dfi-api")
    api_thr.start()

    total_threads = 7 + len(eye_threads) + (1 if dispatcher else 0) + (1 if heartbeat else 0)
    log.info("WinHunt agent started — vm_id=%s, api=%s:%d, threads=%d",
             cfg.vm_id, cfg.mgmt_nic_ip, cfg.agent_port, total_threads)

    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    finally:
        log.info("shutting down — flushing active flows")
        flow_table.emit_all()
        buffer.close()
        log.info("shutdown complete")


if __name__ == "__main__":
    main()
