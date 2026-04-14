"""Breadcrumb tracker eye sensor — monitors planted credential consumption.

Not a thread. Tracks planted credential files and detects when attackers
access them (via 4663 object access events). Emits CREDENTIAL_THEFT
observations when breadcrumbs are consumed.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

from ..evidence_bits import CREDENTIAL_THEFT
from ..observation import (
    BREADCRUMB_CONSUMED,
    CREDENTIAL_ACCESS,
    PRIORITY_IMMEDIATE,
)

log = logging.getLogger("winhunt.eyes.breadcrumb_tracker")


class BreadcrumbTracker:
    """Tracks planted credential files and detects attacker consumption.

    Credential files ("breadcrumbs") are planted at strategic locations
    on the honeypot. When an attacker accesses one, a high-priority
    CREDENTIAL_THEFT observation is emitted.
    """

    def __init__(self, config: Any, buffer: Any) -> None:
        self.config = config
        self.buffer = buffer
        # In-memory registry: path (normalized) -> breadcrumb info
        self._breadcrumbs: dict[str, dict[str, Any]] = {}
        # Ensure breadcrumbs table exists in buffer
        self._init_table()

    def _init_table(self) -> None:
        """Create breadcrumbs table in buffer if it doesn't exist."""
        try:
            conn = self.buffer._get_conn()
            conn.execute(
                "CREATE TABLE IF NOT EXISTS breadcrumbs ("
                "  path TEXT PRIMARY KEY,"
                "  credential_type TEXT NOT NULL,"
                "  target_service TEXT,"
                "  target_host TEXT,"
                "  planted_at TEXT NOT NULL,"
                "  consumed_at TEXT,"
                "  consumer_ip TEXT"
                ")"
            )
            conn.commit()
        except Exception:
            log.exception("Failed to initialize breadcrumbs table")

    def register_breadcrumb(self, credential_type: str, planted_path: str,
                            target_service: str | None = None,
                            target_host: str | None = None) -> None:
        """Register a planted credential file for monitoring.

        Args:
            credential_type: Type of credential (e.g. 'ssh_key', 'rdp_password',
                'mssql_config', 'web_credential').
            planted_path: Full path to the planted file on the honeypot.
            target_service: Service the credential targets (e.g. 'ssh', 'rdp').
            target_host: Host the credential targets (e.g. '172.16.3.200').
        """
        norm_path = planted_path.strip().lower().replace("/", "\\")
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        self._breadcrumbs[norm_path] = {
            "credential_type": credential_type,
            "planted_path": planted_path,
            "target_service": target_service,
            "target_host": target_host,
            "planted_at": now_iso,
            "consumed_at": None,
            "consumer_ip": None,
        }

        # Persist to buffer table
        try:
            conn = self.buffer._get_conn()
            with conn:
                conn.execute(
                    "INSERT OR REPLACE INTO breadcrumbs"
                    "(path, credential_type, target_service, target_host, planted_at) "
                    "VALUES(?,?,?,?,?)",
                    (norm_path, credential_type, target_service, target_host, now_iso),
                )
        except Exception:
            log.exception("Failed to persist breadcrumb: %s", planted_path)

        log.info(
            "Breadcrumb registered: %s (%s) -> %s@%s",
            planted_path, credential_type,
            target_service or "?", target_host or "?",
        )

    def check_access(self, path: str, accessor_ip: str | None,
                     ts: float) -> bool:
        """Check if a file access event targets a planted breadcrumb.

        Called on 4663 object access events. If the accessed path matches
        a registered breadcrumb, emits a CREDENTIAL_THEFT observation and
        updates the breadcrumbs table.

        Args:
            path: File path from the 4663 event ObjectName field.
            accessor_ip: Source IP of the accessor (from logon map), or None.
            ts: Event timestamp as Unix epoch float.

        Returns:
            True if the access was a breadcrumb consumption, False otherwise.
        """
        if not path:
            return False

        norm_path = path.strip().lower().replace("/", "\\")

        if norm_path not in self._breadcrumbs:
            return False

        bc = self._breadcrumbs[norm_path]

        # Already consumed — don't alert again
        if bc["consumed_at"] is not None:
            return False

        consumed_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))

        # Mark as consumed
        bc["consumed_at"] = consumed_iso
        bc["consumer_ip"] = accessor_ip

        log.warning(
            "Breadcrumb consumed: %s by %s at %s",
            bc["planted_path"], accessor_ip or "unknown", consumed_iso,
        )

        # Update buffer table
        try:
            conn = self.buffer._get_conn()
            with conn:
                conn.execute(
                    "UPDATE breadcrumbs SET consumed_at=?, consumer_ip=? WHERE path=?",
                    (consumed_iso, accessor_ip, norm_path),
                )
        except Exception:
            log.exception("Failed to update breadcrumb consumption: %s", norm_path)

        # Emit observation
        detail = {
            "planted_path": bc["planted_path"],
            "credential_type": bc["credential_type"],
            "target_service": bc["target_service"],
            "target_host": bc["target_host"],
            "consumer_ip": accessor_ip,
            "planted_at": bc["planted_at"],
            "consumed_at": consumed_iso,
        }
        self.buffer.insert_observation(
            ts=ts,
            vm_id=self.config.vm_id,
            obs_type=BREADCRUMB_CONSUMED,
            session_id=None,
            source_ip=accessor_ip,
            process_pid=0,
            evidence_bits=CREDENTIAL_THEFT,
            priority=PRIORITY_IMMEDIATE,
            detail=json.dumps(detail),
        )

        return True

    def get_breadcrumbs(self) -> list[dict[str, Any]]:
        """Return all registered breadcrumbs with their status."""
        return list(self._breadcrumbs.values())

    def get_consumed(self) -> list[dict[str, Any]]:
        """Return only consumed breadcrumbs."""
        return [bc for bc in self._breadcrumbs.values() if bc["consumed_at"] is not None]
