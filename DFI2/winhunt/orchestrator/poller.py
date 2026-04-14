#!/usr/bin/env python3
"""WinHunt Poller — pulls data from agent API via CT112, inserts into ClickHouse.

Runs on PV1 as a systemd service. Uses pct exec to proxy API calls through
CT112 (which has network access to the agent at 172.16.3.160:9200).

Data flow:
  PV1 poller → pct exec 112 → curl agent:9200/api/* → JSON
  PV1 poller → urllib POST localhost:8123 → ClickHouse INSERT

Usage:
  python3 poller.py                    # run with defaults
  python3 poller.py --once             # single poll cycle
  python3 poller.py --interval 15      # poll every 15s
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import subprocess
import sys
import time
from typing import Any
from urllib import error, parse, request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("winhunt.poller")

# ── Configuration ──

AGENT_IP = os.environ.get("WH_AGENT_IP", "172.16.3.160")
AGENT_PORT = int(os.environ.get("WH_AGENT_PORT", "9200"))
CH_HOST = os.environ.get("WH_CH_HOST", "localhost")
CH_PORT = int(os.environ.get("WH_CH_PORT", "8123"))
CH_DB = os.environ.get("WH_CH_DB", "dfi")
POLL_INTERVAL = int(os.environ.get("WH_POLL_INTERVAL", "30"))
BATCH_LIMIT = int(os.environ.get("WH_BATCH_LIMIT", "5000"))

_running = True


def _signal_handler(signum, frame):
    global _running
    log.info("received signal %d, shutting down", signum)
    _running = False


signal.signal(signal.SIGTERM, _signal_handler)
signal.signal(signal.SIGINT, _signal_handler)


# ── Agent API (via CT112 proxy) ──

def agent_get(path: str) -> Any:
    """GET from agent API via pct exec 112 -- curl."""
    url = f"http://{AGENT_IP}:{AGENT_PORT}{path}"
    cmd = ["pct", "exec", "112", "--", "curl", "-s", "--connect-timeout", "10",
           "--max-time", "30", url]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        if result.returncode != 0:
            log.warning("agent GET %s failed: %s", path, result.stderr[:200])
            return None
        if not result.stdout.strip():
            return None
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        log.warning("agent GET %s timed out", path)
        return None
    except json.JSONDecodeError as exc:
        log.warning("agent GET %s bad JSON: %s", path, exc)
        return None


def agent_post(path: str, data: dict) -> Any:
    """POST to agent API via pct exec 112 -- curl."""
    url = f"http://{AGENT_IP}:{AGENT_PORT}{path}"
    payload = json.dumps(data)
    cmd = ["pct", "exec", "112", "--", "curl", "-s", "--connect-timeout", "10",
           "--max-time", "30", "-X", "POST",
           "-H", "Content-Type: application/json",
           "-d", payload, url]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        if result.returncode != 0:
            log.warning("agent POST %s failed: %s", path, result.stderr[:200])
            return None
        if not result.stdout.strip():
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        log.warning("agent POST %s error: %s", path, exc)
        return None


# ── ClickHouse HTTP insert ──

def ch_insert(table: str, rows: list[dict]) -> int:
    """Insert rows into ClickHouse via HTTP JSONEachRow."""
    if not rows:
        return 0
    query = parse.quote(f"INSERT INTO {table} FORMAT JSONEachRow", safe="")
    url = f"http://{CH_HOST}:{CH_PORT}/?database={CH_DB}&query={query}"
    # Build NDJSON payload
    lines = []
    for row in rows:
        # Strip pulled field — not in CH schema
        clean = {k: v for k, v in row.items() if k != "pulled"}
        lines.append(json.dumps(clean, separators=(",", ":")))
    payload = ("\n".join(lines) + "\n").encode("utf-8")

    req_obj = request.Request(url=url, data=payload, method="POST")
    req_obj.add_header("Content-Type", "application/json")
    try:
        with request.urlopen(req_obj, timeout=60) as resp:
            if resp.status >= 300:
                raise RuntimeError(f"CH insert {table} status={resp.status}")
        return len(rows)
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore")
        log.error("CH insert %s HTTP %d: %s", table, exc.code, body[:500])
        return 0
    except Exception as exc:
        log.error("CH insert %s error: %s", table, exc)
        return 0


# ── Poll cycle ──

def poll_flows() -> int:
    """Pull unpulled flows, insert into CH, ack."""
    rows = agent_get(f"/api/flows?pulled=0&limit={BATCH_LIMIT}")
    if not rows:
        return 0
    count = ch_insert("wh_flows", rows)
    if count > 0:
        flow_ids = [r["flow_id"] for r in rows[:count]]
        agent_post("/api/ack/flows", {"flow_ids": flow_ids})
        log.info("flows: %d ingested, %d acked", count, len(flow_ids))
    return count


def poll_events() -> int:
    """Pull unpulled events, insert into CH, ack."""
    rows = agent_get(f"/api/events?limit={BATCH_LIMIT}")
    if not rows:
        return 0
    count = ch_insert("wh_events", rows)
    if count > 0:
        max_seq = max(r["seq"] for r in rows[:count])
        agent_post("/api/ack/events", {"through_seq": max_seq})
        log.info("events: %d ingested, acked through seq=%d", count, max_seq)
    return count


def poll_packets() -> int:
    """Pull unpulled packets, insert into CH."""
    rows = agent_get(f"/api/packets?limit={BATCH_LIMIT}")
    if not rows:
        return 0
    count = ch_insert("wh_packets", rows)
    if count > 0:
        log.info("packets: %d ingested", count)
    return count


def poll_fingerprints() -> int:
    """Pull unpulled fingerprints, insert into CH."""
    rows = agent_get(f"/api/fingerprints?limit={BATCH_LIMIT}")
    if not rows:
        return 0
    count = ch_insert("wh_fingerprints", rows)
    if count > 0:
        log.info("fingerprints: %d ingested", count)
    return count


def poll_observations() -> int:
    """Pull unpulled observations, insert into CH, ack."""
    rows = agent_get(f"/api/observations?limit={BATCH_LIMIT}")
    if not rows:
        return 0
    count = ch_insert("wh_observations", rows)
    if count > 0:
        max_id = max(r["obs_id"] for r in rows[:count])
        agent_post("/api/ack/observations", {"through_id": max_id})
        log.info("observations: %d ingested, acked through id=%d", count, max_id)
    return count


def poll_source_stats() -> int:
    """Pull source stats (replace on each poll)."""
    rows = agent_get("/api/source_stats")
    if not rows:
        return 0
    count = ch_insert("wh_source_stats", rows)
    if count > 0:
        log.info("source_stats: %d ingested", count)
    return count


def poll_cycle() -> dict[str, int]:
    """Run one full poll cycle across all data types."""
    results = {}
    results["flows"] = poll_flows()
    results["events"] = poll_events()
    results["packets"] = poll_packets()
    results["fingerprints"] = poll_fingerprints()
    results["observations"] = poll_observations()
    results["source_stats"] = poll_source_stats()
    total = sum(results.values())
    if total > 0:
        log.info("poll cycle complete: %s", results)
    return results


# ── Health check ──

def health_check() -> bool:
    """Quick health check — can we reach the agent?"""
    data = agent_get("/api/health")
    if data:
        log.info("agent healthy: uptime=%ds, capture=%s, events=%d",
                 data.get("uptime_sec", 0),
                 data.get("pcap", {}).get("capture_running", False),
                 data.get("evidence", {}).get("events_processed", 0))
        return True
    log.warning("agent unreachable")
    return False


# ── Main loop ──

def main():
    parser = argparse.ArgumentParser(description="WinHunt Poller")
    parser.add_argument("--once", action="store_true", help="single poll cycle")
    parser.add_argument("--interval", type=int, default=POLL_INTERVAL,
                        help=f"poll interval seconds (default {POLL_INTERVAL})")
    parser.add_argument("--health", action="store_true", help="health check only")
    args = parser.parse_args()

    log.info("WinHunt Poller starting — agent=%s:%d CH=%s:%d/%s interval=%ds",
             AGENT_IP, AGENT_PORT, CH_HOST, CH_PORT, CH_DB, args.interval)

    if args.health:
        ok = health_check()
        sys.exit(0 if ok else 1)

    if args.once:
        health_check()
        poll_cycle()
        return

    # Continuous polling loop
    health_check()
    cycle = 0
    while _running:
        try:
            poll_cycle()
        except Exception as exc:
            log.error("poll cycle error: %s", exc)

        cycle += 1
        # Periodic health check every 10 cycles
        if cycle % 10 == 0:
            health_check()

        # Sleep in small increments for responsive shutdown
        for _ in range(args.interval):
            if not _running:
                break
            time.sleep(1)

    log.info("poller stopped")


if __name__ == "__main__":
    main()
