"""Contamination firewall — logs every command executed by the agent.

This log allows the evidence pipeline to cross-reference agent-executed
commands and exclude them from attacker classification.  Each entry is a
single JSON line so external tools can stream-parse the file.
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("winhunt.hand.command_log")


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class CommandLog:
    """Append-only JSONL log of every command dispatched through the hand."""

    def __init__(self, log_path: str) -> None:
        self._path = log_path
        self._lock = threading.Lock()
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        # Open in append mode; create if missing
        self._fh = open(log_path, "a", encoding="utf-8")
        log.info("command_log open: %s", log_path)

    # ── public ──

    def log_command(
        self,
        command_id: str,
        command: str,
        args: dict,
        source: str,
        ts: str | None = None,
    ) -> None:
        """Write a command-dispatched entry.

        Parameters
        ----------
        command_id : str
            UUID assigned by the dispatcher.
        command : str
            Handler name (e.g. ``health_check``).
        args : dict
            Sanitised copy of the command arguments.
        source : str
            ``"agent"`` or ``"orchestrator"`` — who issued the command.
        ts : str, optional
            ISO 8601 timestamp; defaults to now-UTC.
        """
        entry = {
            "type": "command",
            "ts": ts or _iso_now(),
            "command_id": command_id,
            "command": command,
            "args_summary": self._summarise_args(args),
            "source": source,
        }
        self._write(entry)

    def log_result(
        self,
        command_id: str,
        status: str,
        duration_ms: int,
    ) -> None:
        """Write a command-result entry.

        Parameters
        ----------
        command_id : str
            UUID matching the earlier ``log_command`` call.
        status : str
            ``"ok"`` or ``"error"``.
        duration_ms : int
            Wall-clock execution time in milliseconds.
        """
        entry = {
            "type": "result",
            "ts": _iso_now(),
            "command_id": command_id,
            "status": status,
            "duration_ms": duration_ms,
        }
        self._write(entry)

    def close(self) -> None:
        with self._lock:
            if self._fh and not self._fh.closed:
                self._fh.close()

    # ── internal ──

    @staticmethod
    def _summarise_args(args: dict) -> dict:
        """Return a safe summary — truncate large values to avoid bloat."""
        out: dict = {}
        for k, v in args.items():
            if isinstance(v, str) and len(v) > 256:
                out[k] = v[:256] + "...<truncated>"
            elif isinstance(v, (bytes, bytearray)):
                out[k] = f"<bytes len={len(v)}>"
            else:
                out[k] = v
        return out

    def _write(self, entry: dict) -> None:
        line = json.dumps(entry, separators=(",", ":"), default=str) + "\n"
        with self._lock:
            try:
                self._fh.write(line)
                self._fh.flush()
            except Exception:
                log.exception("failed to write command log entry")
