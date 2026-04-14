"""Prediction-to-evidence feedback loop.

Compares XGBoost predictions against hard evidence from Windows Event Log
evidence_bits. Mismatches produce gold correction samples for model
retraining. Tracks per-class accuracy over time.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from .. import evidence_bits as eb

log = logging.getLogger("winhunt.inference.feedback")

# Evidence bit patterns -> expected label mapping
# These encode what the evidence "proves" regardless of what the model predicted.
# Multiple patterns can match; the highest-severity label wins.
_EVIDENCE_LABEL_MAP: list[tuple[int, int]] = [
    # AUTH_SUCCESS + OUTBOUND_C2 + FILE_DOWNLOAD => COMPROMISE (4)
    (eb.AUTH_SUCCESS | eb.OUTBOUND_C2 | eb.FILE_DOWNLOAD, 4),
    # AUTH_SUCCESS + OUTBOUND_C2 => COMPROMISE (4)
    (eb.AUTH_SUCCESS | eb.OUTBOUND_C2, 4),
    # AUTH_SUCCESS + SUSPICIOUS_COMMAND => EXPLOIT (3)
    (eb.AUTH_SUCCESS | eb.SUSPICIOUS_COMMAND, 3),
    # AUTH_SUCCESS + PRIVILEGE_ESCALATION => EXPLOIT (3)
    (eb.AUTH_SUCCESS | eb.PRIVILEGE_ESCALATION, 3),
    # AUTH_SUCCESS + SERVICE_INSTALL => EXPLOIT (3)
    (eb.AUTH_SUCCESS | eb.SERVICE_INSTALL, 3),
    # AUTH_SUCCESS + CREDENTIAL_THEFT => EXPLOIT (3)
    (eb.AUTH_SUCCESS | eb.CREDENTIAL_THEFT, 3),
    # AUTH_SUCCESS + LATERAL_MOVEMENT => EXPLOIT (3)
    (eb.AUTH_SUCCESS | eb.LATERAL_MOVEMENT, 3),
    # AUTH_FAILURE (repeated) => BRUTEFORCE (2)
    (eb.AUTH_FAILURE, 2),
    # AUTH_SUCCESS alone (no post-exploitation) => BRUTEFORCE (2) -- successful brute
    # NOTE: Single AUTH_SUCCESS without attack evidence could be benign,
    # but in a honeypot context it's at least BRUTEFORCE success.
    (eb.AUTH_SUCCESS, 2),
]


def _evidence_to_label(evidence_bits_val: int) -> int | None:
    """Map evidence bits to expected label.

    Returns the most severe (highest-numbered) label that matches
    the evidence pattern, or None if evidence is too sparse to label.
    """
    if evidence_bits_val == 0:
        return None  # No evidence -- cannot determine label

    best_label: int | None = None
    for pattern, label in _EVIDENCE_LABEL_MAP:
        if (evidence_bits_val & pattern) == pattern:
            if best_label is None or label > best_label:
                best_label = label

    return best_label


class FeedbackLoop:
    """Compares predictions against evidence and tracks model performance.

    Evidence bits from Windows Event Log are treated as ground truth.
    When a prediction disagrees with evidence, a correction record is
    generated for model retraining.
    """

    def __init__(self, config: Any, buffer: Any) -> None:
        """Initialize feedback loop.

        Args:
            config: AgentConfig.
            buffer: AgentBuffer for reading evidence and writing corrections.
        """
        self.config = config
        self.buffer = buffer

        # Performance tracking (binary: 0=NORM, 1=ATTACK)
        self._confirmed: int = 0
        self._contradicted: int = 0
        self._per_class_correct: dict[int, int] = {0: 0, 1: 0}
        self._per_class_total: dict[int, int] = {0: 0, 1: 0}
        self._corrections: list[dict[str, Any]] = []

    def compare(
        self,
        flow_id: str,
        predicted_label: int,
        evidence_bits_val: int,
    ) -> dict[str, Any] | None:
        """Compare a binary prediction against evidence bits.

        The model predicts binary (0=NORM, 1=ATTACK). Evidence maps to
        specific attack classes (2=BRUTE, 3=EXPLOIT, 4=COMPROMISE) which
        all collapse to binary ATTACK (1) for comparison. Correction
        samples preserve the specific evidence label for future multi-class
        retraining.

        Args:
            flow_id: The flow identifier.
            predicted_label: Model's predicted class (0=NORM, 1=ATTACK).
            evidence_bits_val: Accumulated evidence_bits for the flow's session.

        Returns:
            A correction dict if there is a mismatch, None if confirmed or
            evidence is insufficient to judge.
        """
        evidence_label = _evidence_to_label(evidence_bits_val)

        if evidence_label is None:
            log.debug("feedback: flow %s -- insufficient evidence (bits=0x%04x)",
                      flow_id[:12], evidence_bits_val)
            return None

        # Collapse evidence to binary: any attack label (>=2) -> 1 (ATTACK)
        evidence_binary = 1 if evidence_label >= 2 else 0

        # Track per-class stats (binary)
        self._per_class_total[evidence_binary] = self._per_class_total.get(evidence_binary, 0) + 1

        if predicted_label == evidence_binary:
            self._confirmed += 1
            self._per_class_correct[evidence_binary] = self._per_class_correct.get(evidence_binary, 0) + 1
            log.debug("feedback: flow %s confirmed (predicted=%d, evidence_binary=%d, evidence_specific=%d)",
                      flow_id[:12], predicted_label, evidence_binary, evidence_label)
            return None

        # Mismatch -- gold correction sample
        self._contradicted += 1

        from .engine import LABELS
        # Specific evidence label names for correction records
        _SPECIFIC_LABELS = {2: "BRUTEFORCE", 3: "EXPLOIT", 4: "COMPROMISE"}

        correction = {
            "flow_id": flow_id,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "predicted_label": predicted_label,
            "predicted_name": LABELS.get(predicted_label, f"UNKNOWN_{predicted_label}"),
            "evidence_label": evidence_label,
            "evidence_name": _SPECIFIC_LABELS.get(evidence_label, f"UNKNOWN_{evidence_label}"),
            "evidence_binary": evidence_binary,
            "evidence_bits": evidence_bits_val,
            "evidence_bits_desc": eb.describe_bits(evidence_bits_val),
        }

        self._corrections.append(correction)
        log.info(
            "feedback: flow %s MISMATCH predicted=%s evidence=%s (bits=%s)",
            flow_id[:12],
            correction["predicted_name"],
            correction["evidence_name"],
            ",".join(correction["evidence_bits_desc"]),
        )

        return correction

    def daily_stats(self) -> dict[str, Any]:
        """Return performance metrics (binary: NORM/ATTACK).

        Returns:
            Dict with confirmed count, contradicted count, and per-class accuracy.
        """
        from .engine import LABELS

        per_class_accuracy: dict[str, float | None] = {}
        for cls_id in (0, 1):
            total = self._per_class_total.get(cls_id, 0)
            correct = self._per_class_correct.get(cls_id, 0)
            name = LABELS.get(cls_id, f"UNKNOWN_{cls_id}")
            per_class_accuracy[name] = round(correct / total, 4) if total > 0 else None

        total = self._confirmed + self._contradicted
        return {
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "confirmed": self._confirmed,
            "contradicted": self._contradicted,
            "total_evaluated": total,
            "overall_accuracy": round(self._confirmed / total, 4) if total > 0 else None,
            "per_class_accuracy": per_class_accuracy,
            "corrections_pending": len(self._corrections),
        }

    def update_performance(self, date: str, stats: dict[str, Any]) -> None:
        """Write performance metrics to model_performance table.

        Args:
            date: Date string (YYYY-MM-DD).
            stats: Stats dict from daily_stats().
        """
        # Store as a special event in the buffer for upstream collection
        self.buffer.insert_event(
            ts=time.time(),
            vm_id=self.config.vm_id,
            source_ip=None,
            source_port=0,
            service="inference",
            event_type="model_performance",
            evidence_bits=0,
            raw_event_id=None,
            raw_channel=None,
            detail={
                "date": date,
                "stats": stats,
            },
        )
        log.info("model performance for %s: confirmed=%d contradicted=%d accuracy=%s",
                 date, stats.get("confirmed", 0), stats.get("contradicted", 0),
                 stats.get("overall_accuracy"))

    def get_corrections(self) -> list[dict[str, Any]]:
        """Return accumulated correction samples (for retraining export)."""
        return list(self._corrections)

    def clear_corrections(self) -> None:
        """Clear the corrections list after export."""
        self._corrections.clear()
