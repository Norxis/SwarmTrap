"""Local kill-chain labeler -- combines XGB predictions + evidence observations."""
from __future__ import annotations

import logging
import time
from typing import Any

from . import evidence_bits as eb

log = logging.getLogger("winhunt.labeler")

# Kill-chain label codes
BENIGN = 0
RECON = 1
BRUTEFORCE = 2
EXPLOIT = 3
COMPROMISE = 4

LABEL_NAMES = {
    BENIGN: "BENIGN",
    RECON: "RECON",
    BRUTEFORCE: "BRUTEFORCE",
    EXPLOIT: "EXPLOIT",
    COMPROMISE: "COMPROMISE",
}


class SessionLabeler:
    """Applies kill-chain rules to sessions using observations and predictions."""

    def __init__(self, config: Any, buffer: Any) -> None:
        self.config = config
        self.buffer = buffer
        self._labeled: set[str] = set()

    # ── public API ──

    def label_session(self, session_id: str, source_ip: str) -> dict:
        """Query observations and predictions for a session/source_ip,
        apply kill-chain rules and return a label result dict.

        Rules (checked in priority order):
          - auth success + download + execute + outbound -> COMPROMISE (4)
          - auth success + suspicious command            -> EXPLOIT (3)
          - >= 3 auth failures                           -> BRUTEFORCE (2)
          - external login, no commands                  -> RECON (1)
          - none of the above                            -> BENIGN (0)

        Returns:
            {
                "session_id": str,
                "source_ip": str,
                "label": int,
                "label_name": str,
                "evidence_bits": int,
                "confidence": float,
                "rule_matched": str,
            }
        """
        obs = self._get_observations(session_id, source_ip)
        preds = self._get_predictions(session_id, source_ip)

        combined_bits = 0
        for o in obs:
            combined_bits |= o.get("evidence_bits", 0)

        has_auth_success = bool(combined_bits & eb.AUTH_SUCCESS)
        has_auth_failure = bool(combined_bits & eb.AUTH_FAILURE)
        has_suspicious = bool(combined_bits & eb.SUSPICIOUS_COMMAND)
        has_download = bool(combined_bits & eb.FILE_DOWNLOAD)
        has_process = bool(combined_bits & eb.PROCESS_CREATE)
        has_outbound = bool(combined_bits & eb.OUTBOUND_C2)

        auth_failure_count = sum(
            1 for o in obs
            if o.get("evidence_bits", 0) & eb.AUTH_FAILURE
        )

        # Confidence from prediction engine (if available)
        pred_confidence = 0.0
        if preds:
            pred_confidence = max(p.get("confidence", 0.0) for p in preds)

        # Rule evaluation in priority order (highest severity first)
        label = BENIGN
        rule = "none"
        confidence = 0.0

        # COMPROMISE: auth success + download + execute + outbound
        if has_auth_success and has_download and has_process and has_outbound:
            label = COMPROMISE
            rule = "auth_success+download+execute+outbound"
            confidence = max(0.95, pred_confidence)

        # EXPLOIT: auth success + suspicious command
        elif has_auth_success and has_suspicious:
            label = EXPLOIT
            rule = "auth_success+suspicious_command"
            confidence = max(0.85, pred_confidence)

        # BRUTEFORCE: >= 3 auth failures
        elif auth_failure_count >= 3:
            label = BRUTEFORCE
            rule = "auth_failures_ge_3"
            confidence = min(1.0, 0.5 + auth_failure_count * 0.1)

        # RECON: external login attempt, no commands
        elif (has_auth_failure or has_auth_success) and not has_suspicious and not has_process:
            label = RECON
            rule = "external_login_no_commands"
            confidence = max(0.60, pred_confidence)

        # BENIGN
        else:
            label = BENIGN
            rule = "none"
            confidence = max(0.50, 1.0 - pred_confidence) if pred_confidence > 0 else 0.50

        result = {
            "session_id": session_id,
            "source_ip": source_ip,
            "label": label,
            "label_name": LABEL_NAMES[label],
            "evidence_bits": combined_bits,
            "confidence": round(confidence, 4),
            "rule_matched": rule,
        }

        self._labeled.add(f"{session_id}:{source_ip}")
        log.info(
            "labeled session=%s src=%s label=%s confidence=%.2f rule=%s",
            session_id, source_ip, LABEL_NAMES[label], confidence, rule,
        )
        return result

    def label_all_pending(self) -> list[dict]:
        """Query recent unlabeled sessions and label each one.

        Returns list of label result dicts.
        """
        results: list[dict] = []
        pending = self._get_pending_sessions()

        for session_id, source_ip in pending:
            key = f"{session_id}:{source_ip}"
            if key in self._labeled:
                continue
            try:
                result = self.label_session(session_id, source_ip)
                results.append(result)
            except Exception:
                log.exception(
                    "failed to label session=%s src=%s",
                    session_id, source_ip,
                )

        if results:
            log.info("labeled %d pending sessions", len(results))
        return results

    # ── internal helpers ──

    def _get_observations(self, session_id: str, source_ip: str) -> list[dict]:
        """Retrieve observations for a session from the buffer.

        Tries buffer.get_observations_by_session() if available,
        otherwise falls back to scanning events.
        """
        if hasattr(self.buffer, "get_observations_by_session"):
            rows = self.buffer.get_observations_by_session(session_id, source_ip)
            return [dict(r) if not isinstance(r, dict) else r for r in rows]

        # Fallback: scan events for this source IP
        if hasattr(self.buffer, "get_events"):
            rows = self.buffer.get_events(limit=5000)
            return [
                dict(r) if not isinstance(r, dict) else r
                for r in rows
                if (r.get("source_ip") if isinstance(r, dict)
                    else r["source_ip"]) == source_ip
            ]
        return []

    def _get_predictions(self, session_id: str, source_ip: str) -> list[dict]:
        """Retrieve ML predictions for a session if available."""
        if hasattr(self.buffer, "get_predictions_by_session"):
            rows = self.buffer.get_predictions_by_session(session_id, source_ip)
            return [dict(r) if not isinstance(r, dict) else r for r in rows]
        return []

    def _get_pending_sessions(self) -> list[tuple[str, str]]:
        """Get list of (session_id, source_ip) pairs that need labeling."""
        if hasattr(self.buffer, "get_unlabeled_sessions"):
            rows = self.buffer.get_unlabeled_sessions()
            return [(r["session_id"], r["source_ip"]) for r in rows]

        # Fallback: get recent observations and extract unique sessions
        seen: dict[str, str] = {}
        if hasattr(self.buffer, "get_events"):
            rows = self.buffer.get_events(limit=5000, pulled=0)
            for r in rows:
                src_ip = r["source_ip"] if not isinstance(r, dict) else r.get("source_ip")
                if src_ip and src_ip not in seen:
                    session_key = r["service"] if not isinstance(r, dict) else r.get("service", "unknown")
                    seen[src_ip] = session_key

        return [(sid, sip) for sip, sid in seen.items()]
