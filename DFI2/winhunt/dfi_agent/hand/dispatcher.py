"""Command queue + dispatcher thread.

Dequeues command dicts, dispatches to handlers in ``handlers.py``,
stores results keyed by ``command_id``.  Rate-limited via a token
bucket so burst + sustained rates are honoured.
"""
from __future__ import annotations

import logging
import queue
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from .command_log import CommandLog
from .handlers import COMMAND_REGISTRY

log = logging.getLogger("winhunt.hand.dispatcher")


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ── token bucket ─────────────────────────────────────────────────────

class _TokenBucket:
    """Simple token-bucket rate limiter (thread-safe)."""

    def __init__(self, rate: float, burst: int) -> None:
        self._rate = rate          # tokens per second (sustained)
        self._burst = burst        # max tokens (burst cap)
        self._tokens = float(burst)
        self._ts = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 5.0) -> bool:
        """Block until a token is available or *timeout* expires."""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._ts
                self._ts = now
                self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)


# ── dispatcher ───────────────────────────────────────────────────────

class CommandDispatcher(threading.Thread):
    """Daemon thread that drains a command queue and dispatches handlers.

    Parameters
    ----------
    config : AgentConfig
        Agent configuration.  The dispatcher reads ``config.hand.*``
        attributes (via ``getattr`` with defaults) for tuning.
    buffer : AgentBuffer
        Shared SQLite buffer (not currently used but available for
        handlers that need DB access).
    stop_event : threading.Event
        Cooperative shutdown signal.
    """

    def __init__(
        self,
        config: Any,
        buffer: Any,
        stop_event: threading.Event,
    ) -> None:
        super().__init__(name="dfi-hand", daemon=True)
        self._config = config
        self._buffer = buffer
        self._stop = stop_event

        # Hand-specific tunables (read from config.hand.* with defaults)
        hand = getattr(config, "hand", None)
        max_queue = getattr(hand, "max_queue_size", 256) if hand else 256
        rate_per_sec = getattr(hand, "rate_limit_per_sec", 10.0) if hand else 10.0
        burst = getattr(hand, "rate_limit_burst", 20) if hand else 20
        default_timeout = getattr(hand, "default_timeout", 30) if hand else 30
        log_path = getattr(hand, "command_log_path", None) if hand else None

        self._default_timeout = default_timeout
        self._queue: queue.Queue[dict] = queue.Queue(maxsize=max_queue)
        self._results: dict[str, dict] = {}
        self._results_lock = threading.Lock()
        self._bucket = _TokenBucket(rate=rate_per_sec, burst=burst)

        # Command log — contamination firewall
        if log_path is None:
            log_dir = getattr(config, "log_dir", ".")
            log_path = f"{log_dir}/command_log.jsonl"
        self._cmd_log = CommandLog(log_path)

        log.info(
            "dispatcher init: queue=%d, rate=%.1f/s, burst=%d, timeout=%ds",
            max_queue, rate_per_sec, burst, default_timeout,
        )

    # ── public API ───────────────────────────────────────────────────

    def submit(self, command_dict: dict) -> str:
        """Validate, enqueue a command, and return its ``command_id``.

        Parameters
        ----------
        command_dict : dict
            Must contain at least ``{"command": str}``.
            Optional keys: ``args`` (dict), ``timeout`` (int),
            ``source`` (str, default ``"orchestrator"``).

        Returns
        -------
        str
            The assigned ``command_id`` (UUID4).

        Raises
        ------
        ValueError
            If required fields are missing or invalid.
        queue.Full
            If the command queue is at capacity.
        """
        # ── schema validation ──
        cmd_name = command_dict.get("command")
        if not cmd_name or not isinstance(cmd_name, str):
            raise ValueError("command_dict must contain a non-empty 'command' string")
        if cmd_name not in COMMAND_REGISTRY:
            raise ValueError(f"unknown command: '{cmd_name}'")

        args = command_dict.get("args", {})
        if not isinstance(args, dict):
            raise ValueError("'args' must be a dict")

        timeout = command_dict.get("timeout", self._default_timeout)
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            timeout = self._default_timeout

        source = command_dict.get("source", "orchestrator")
        command_id = uuid.uuid4().hex

        envelope = {
            "command_id": command_id,
            "command": cmd_name,
            "args": args,
            "timeout": int(timeout),
            "source": source,
            "enqueued_at": _iso_now(),
        }

        self._queue.put(envelope, block=True, timeout=5)
        log.debug("enqueued %s [%s] (queue depth %d)", cmd_name, command_id, self._queue.qsize())
        return command_id

    def get_result(self, command_id: str, timeout: float = 30) -> dict | None:
        """Poll for a command result.

        Parameters
        ----------
        command_id : str
            The UUID returned by :meth:`submit`.
        timeout : float
            Maximum seconds to wait (polling interval 0.1 s).

        Returns
        -------
        dict or None
            The result dict if available, else ``None``.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._results_lock:
                result = self._results.pop(command_id, None)
            if result is not None:
                return result
            time.sleep(0.1)
        return None

    # ── thread loop ──────────────────────────────────────────────────

    def run(self) -> None:
        log.info("dispatcher thread started")
        while not self._stop.is_set():
            try:
                envelope = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            command_id = envelope["command_id"]
            cmd_name = envelope["command"]
            args = envelope["args"]
            cmd_timeout = envelope["timeout"]
            source = envelope["source"]

            # Rate limit
            if not self._bucket.acquire(timeout=cmd_timeout):
                result = self._make_result(
                    command_id, cmd_name, "error",
                    {"error": "rate limit exceeded"}, 0,
                )
                self._store_result(command_id, result)
                self._cmd_log.log_command(command_id, cmd_name, args, source)
                self._cmd_log.log_result(command_id, "error", 0)
                continue

            # Log command
            self._cmd_log.log_command(command_id, cmd_name, args, source)

            # Dispatch
            handler = COMMAND_REGISTRY[cmd_name]
            t0 = time.monotonic()
            try:
                data = handler(self._config, args)
                duration_ms = int((time.monotonic() - t0) * 1000)
                result = self._make_result(command_id, cmd_name, "ok", data, duration_ms)
                log.info("%s [%s] ok (%d ms)", cmd_name, command_id, duration_ms)
            except Exception as exc:
                duration_ms = int((time.monotonic() - t0) * 1000)
                result = self._make_result(
                    command_id, cmd_name, "error",
                    {"error": str(exc)}, duration_ms,
                )
                log.error("%s [%s] error (%d ms): %s", cmd_name, command_id, duration_ms, exc)

            self._store_result(command_id, result)
            self._cmd_log.log_result(command_id, result["status"], duration_ms)

        # Shutdown
        self._cmd_log.close()
        log.info("dispatcher thread stopped")

    # ── internal ─────────────────────────────────────────────────────

    @staticmethod
    def _make_result(
        command_id: str,
        command: str,
        status: str,
        data: Any,
        duration_ms: int,
    ) -> dict:
        return {
            "command_id": command_id,
            "command": command,
            "status": status,
            "result": data,
            "duration_ms": duration_ms,
            "ts": _iso_now(),
        }

    def _store_result(self, command_id: str, result: dict) -> None:
        with self._results_lock:
            self._results[command_id] = result
