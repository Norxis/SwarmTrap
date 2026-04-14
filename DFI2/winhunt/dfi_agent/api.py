"""REST API per spec Module 5 — Flask/Waitress.

Binds to mgmt_nic_ip only. Token auth via X-DFI-Token header.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

log = logging.getLogger("winhunt.api")


def create_app(config, buffer, capture_thread=None, evidence_thread=None,
               flow_table=None, command_dispatcher=None):
    """Create Flask app with all spec endpoints."""
    try:
        from flask import Flask, jsonify, request as req
    except ImportError:
        log.warning("flask not installed — API disabled")
        return None

    app = Flask("winhunt")
    start_time = time.time()

    def _check_token():
        if config.token:
            tok = req.headers.get("X-DFI-Token", "")
            if tok != config.token:
                return jsonify({"error": "unauthorized"}), 401
        return None

    @app.before_request
    def auth():
        return _check_token()

    @app.route("/api/health")
    def health():
        uptime = time.time() - start_time
        pcap_info: dict[str, Any] = {"capture_running": False}
        if capture_thread:
            pcap_info.update({
                "capture_running": capture_thread.capture_running,
                "capture_interface": config.pcap.interface,
                "active_flows": flow_table.active_flow_count if flow_table else 0,
                "completed_flows_total": flow_table.flows_emitted if flow_table else 0,
                "unpulled_flows": buffer.get_flow_count(pulled=0),
                "unpulled_packets": buffer.packet_count(pulled=0),
                "unpulled_fingerprints": buffer.fingerprint_count(pulled=0),
                "packets_captured": capture_thread.packets_received,
                "packets_dropped_npcap": capture_thread.packets_dropped,
                "packets_non_ipv4_skipped": capture_thread.packets_non_ipv4_skipped,
                "source_ips_tracked": buffer.source_stats_count(),
            })
        ev_info: dict[str, Any] = {}
        if evidence_thread:
            ev_info.update({
                "events_buffered": buffer.event_count(),
                "unpulled_events": buffer.event_count(pulled=0),
                "logon_map_size": buffer.logon_map_size(),
                "events_processed": evidence_thread.events_processed,
                "ip_extraction_failures": evidence_thread.ip_extraction_failures,
            })
        return jsonify({
            "vm_id": config.vm_id,
            "uptime_sec": int(uptime),
            "pcap": pcap_info,
            "evidence": ev_info,
            "buffer": {
                "db_size_mb": round(buffer.db_size_mb(), 2),
                "wal_size_mb": round(buffer.wal_size_mb(), 2),
            },
        })

    @app.route("/api/attacker_ips")
    def attacker_ips():
        """Return tracked external attacker IPs with counts and reasons."""
        min_count = int(req.args.get("min_count", 1))
        result = []
        if evidence_thread and hasattr(evidence_thread, "_attacker_ips"):
            for ip, info in evidence_thread._attacker_ips.items():
                if info["count"] >= min_count:
                    result.append({
                        "ip": ip,
                        "count": info["count"],
                        "first_seen": info["first_seen"],
                        "last_seen": info["last_seen"],
                        "reasons": sorted(info["reasons"]),
                    })
        result.sort(key=lambda x: -x["count"])
        return jsonify(result)

    @app.route("/api/events")
    def get_events():
        since_seq = int(req.args.get("since_seq", 0))
        limit = min(int(req.args.get("limit", 5000)), 50000)
        rows = buffer.get_events(since_seq=since_seq, limit=limit, pulled=0)
        return jsonify([_row_to_dict(r) for r in rows])

    @app.route("/api/ack/events", methods=["POST"])
    def ack_events():
        data = req.get_json(force=True)
        through_seq = data.get("through_seq", 0)
        count = buffer.ack_events(through_seq)
        return jsonify({"acked": count})

    @app.route("/api/flows")
    def get_flows():
        since_ts = req.args.get("since_ts")
        limit = min(int(req.args.get("limit", 5000)), 50000)
        pulled = int(req.args.get("pulled", 0))
        rows = buffer.get_flows(since_ts=since_ts, limit=limit, pulled=pulled)
        result = []
        for r in rows:
            d = _row_to_dict(r)
            # Omit None values per spec
            result.append({k: v for k, v in d.items() if v is not None})
        return jsonify(result)

    @app.route("/api/packets")
    def get_packets():
        flow_ids = req.args.get("flow_ids", "")
        limit = min(int(req.args.get("limit", 50000)), 100000)
        if flow_ids:
            ids = [fid.strip() for fid in flow_ids.split(",") if fid.strip()]
            rows = buffer.get_packets_by_flows(ids, limit=limit)
        else:
            pulled = int(req.args.get("pulled", 0))
            rows = buffer.get_packets(pulled=pulled, limit=limit)
        return jsonify([_row_to_dict(r) for r in rows])

    @app.route("/api/fingerprints")
    def get_fingerprints():
        flow_ids = req.args.get("flow_ids", "")
        if flow_ids:
            ids = [fid.strip() for fid in flow_ids.split(",") if fid.strip()]
            rows = buffer.get_fingerprints_by_flows(ids)
        else:
            pulled = int(req.args.get("pulled", 0))
            limit = min(int(req.args.get("limit", 50000)), 100000)
            rows = buffer.get_fingerprints(pulled=pulled, limit=limit)
        return jsonify([_row_to_dict(r) for r in rows])

    @app.route("/api/ack/flows", methods=["POST"])
    def ack_flows():
        data = req.get_json(force=True)
        flow_ids = data.get("flow_ids", [])
        buffer.ack_flows(flow_ids)
        return jsonify({"acked": len(flow_ids)})

    @app.route("/api/source_stats")
    def source_stats():
        updated_since = req.args.get("updated_since")
        rows = buffer.get_source_stats(updated_since=updated_since)
        return jsonify([_row_to_dict(r) for r in rows])

    @app.route("/api/pcap/stats")
    def pcap_stats():
        stats: dict[str, Any] = {"capture_running": False}
        if capture_thread:
            stats.update({
                "capture_running": capture_thread.capture_running,
                "packets_received": capture_thread.packets_received,
                "packets_dropped": capture_thread.packets_dropped,
                "packets_non_ipv4_skipped": capture_thread.packets_non_ipv4_skipped,
                "active_flows": flow_table.active_flow_count if flow_table else 0,
                "flows_emitted": flow_table.flows_emitted if flow_table else 0,
            })
        return jsonify(stats)

    # ── Phase 3: Command endpoints ──

    @app.route("/api/command", methods=["POST"])
    def submit_command():
        if not command_dispatcher:
            return jsonify({"error": "command dispatcher not available"}), 503
        data = req.get_json(force=True)
        try:
            cmd_id = command_dispatcher.submit(data)
            return jsonify({"command_id": cmd_id, "status": "queued"})
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/command/<command_id>")
    def get_command_result(command_id: str):
        if not command_dispatcher:
            return jsonify({"error": "command dispatcher not available"}), 503
        timeout = int(req.args.get("timeout", 30))
        result = command_dispatcher.get_result(command_id, timeout=timeout)
        if result is None:
            return jsonify({"error": "not found or still pending"}), 404
        return jsonify(result)

    # ── Phase 5: Predictions endpoints ──

    @app.route("/api/predictions")
    def get_predictions():
        limit = min(int(req.args.get("limit", 5000)), 50000)
        flow_id = req.args.get("flow_id")
        if flow_id:
            rows = buffer.get_predictions_by_flow(flow_id)
        else:
            pulled = int(req.args.get("pulled", 0))
            rows = buffer.get_predictions(pulled=pulled, limit=limit)
        return jsonify([_row_to_dict(r) for r in rows])

    @app.route("/api/ack/predictions", methods=["POST"])
    def ack_predictions():
        data = req.get_json(force=True)
        through_id = data.get("through_id", 0)
        count = buffer.ack_predictions(through_id)
        return jsonify({"acked": count})

    # ── Phase 1: Observations endpoints ──

    @app.route("/api/observations")
    def get_observations():
        limit = min(int(req.args.get("limit", 5000)), 50000)
        session_id = req.args.get("session_id")
        source_ip = req.args.get("source_ip")
        if session_id:
            rows = buffer.get_observations_by_session(session_id)
        elif source_ip:
            since_ts = req.args.get("since_ts")
            rows = buffer.get_observations_by_source(source_ip, since_ts)
        else:
            pulled = int(req.args.get("pulled", 0))
            rows = buffer.get_observations(pulled=pulled, limit=limit)
        return jsonify([_row_to_dict(r) for r in rows])

    @app.route("/api/ack/observations", methods=["POST"])
    def ack_observations():
        data = req.get_json(force=True)
        through_id = data.get("through_id", 0)
        count = buffer.ack_observations(through_id)
        return jsonify({"acked": count})

    return app


def _row_to_dict(row) -> dict[str, Any]:
    """Convert sqlite3.Row to dict."""
    if row is None:
        return {}
    return {k: row[k] for k in row.keys()}


def serve_api(config, buffer, capture_thread=None, evidence_thread=None,
              flow_table=None, stop_event=None, command_dispatcher=None):
    """Start API server. Called from __main__ in a daemon thread."""
    app = create_app(config, buffer, capture_thread, evidence_thread,
                     flow_table, command_dispatcher)
    if app is None:
        return

    host = config.mgmt_nic_ip if config.mgmt_nic_ip != "0.0.0.0" else "0.0.0.0"
    port = config.agent_port

    try:
        from waitress import serve  # type: ignore
        log.info("starting Waitress on %s:%d", host, port)
        serve(app, host=host, port=port, threads=4,
              _quiet=True, channel_timeout=120)
    except ImportError:
        log.warning("waitress not installed — falling back to Flask dev server")
        app.run(host=host, port=port, threaded=True, use_reloader=False)
