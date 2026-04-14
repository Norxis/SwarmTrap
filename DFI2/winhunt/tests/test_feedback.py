"""Unit tests for the feedback loop — prediction vs evidence reconciliation."""
from __future__ import annotations

import time
import unittest
from unittest.mock import MagicMock


class _FeedbackLoop:
    """Simplified feedback loop for testing.

    Compares ML predictions against evidence-based observations.
    Tracks corrections and daily statistics.
    """

    def __init__(self) -> None:
        self._corrections: list[dict] = []
        self._daily_stats: dict[str, dict] = {}

    def evaluate(self, prediction: dict, evidence: dict) -> dict:
        """Compare a prediction against evidence-based ground truth.

        Parameters
        ----------
        prediction : dict
            {"session_id": str, "label": int, "confidence": float}
        evidence : dict
            {"session_id": str, "label": int, "evidence_bits": int}

        Returns
        -------
        dict with:
            - matched: bool
            - correction: dict or None
        """
        pred_label = prediction.get("label", 0)
        ev_label = evidence.get("label", 0)
        session_id = prediction.get("session_id", "")

        day_key = time.strftime("%Y-%m-%d")
        if day_key not in self._daily_stats:
            self._daily_stats[day_key] = {
                "total": 0, "matched": 0, "corrected": 0,
            }
        stats = self._daily_stats[day_key]
        stats["total"] += 1

        if pred_label == ev_label:
            stats["matched"] += 1
            return {"matched": True, "correction": None}

        # Mismatch -> generate correction
        correction = {
            "session_id": session_id,
            "predicted_label": pred_label,
            "evidence_label": ev_label,
            "confidence": prediction.get("confidence", 0.0),
            "evidence_bits": evidence.get("evidence_bits", 0),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self._corrections.append(correction)
        stats["corrected"] += 1

        return {"matched": False, "correction": correction}

    def get_corrections(self) -> list[dict]:
        return list(self._corrections)

    def get_daily_stats(self, day_key: str | None = None) -> dict:
        if day_key is None:
            day_key = time.strftime("%Y-%m-%d")
        return self._daily_stats.get(day_key, {"total": 0, "matched": 0, "corrected": 0})


class TestFeedback(unittest.TestCase):
    def test_confirmed_prediction(self):
        """Prediction matches evidence -> no correction generated."""
        fb = _FeedbackLoop()

        prediction = {"session_id": "sess-1", "label": 2, "confidence": 0.85}
        evidence = {"session_id": "sess-1", "label": 2, "evidence_bits": 0x03}

        result = fb.evaluate(prediction, evidence)

        self.assertTrue(result["matched"])
        self.assertIsNone(result["correction"])
        self.assertEqual(len(fb.get_corrections()), 0)

    def test_contradicted_prediction(self):
        """Prediction does not match evidence -> correction generated."""
        fb = _FeedbackLoop()

        prediction = {"session_id": "sess-2", "label": 0, "confidence": 0.60}
        evidence = {"session_id": "sess-2", "label": 3, "evidence_bits": 0x17}

        result = fb.evaluate(prediction, evidence)

        self.assertFalse(result["matched"])
        self.assertIsNotNone(result["correction"])

        correction = result["correction"]
        self.assertEqual(correction["session_id"], "sess-2")
        self.assertEqual(correction["predicted_label"], 0)
        self.assertEqual(correction["evidence_label"], 3)
        self.assertEqual(correction["confidence"], 0.60)
        self.assertEqual(correction["evidence_bits"], 0x17)

        # Correction should be stored
        self.assertEqual(len(fb.get_corrections()), 1)

    def test_daily_stats(self):
        """Stats aggregation should be correct across multiple evaluations."""
        fb = _FeedbackLoop()

        # 3 matched predictions
        for i in range(3):
            fb.evaluate(
                {"session_id": f"s-{i}", "label": 1, "confidence": 0.90},
                {"session_id": f"s-{i}", "label": 1, "evidence_bits": 0x01},
            )

        # 2 mismatched predictions
        for i in range(3, 5):
            fb.evaluate(
                {"session_id": f"s-{i}", "label": 0, "confidence": 0.50},
                {"session_id": f"s-{i}", "label": 2, "evidence_bits": 0x03},
            )

        stats = fb.get_daily_stats()
        self.assertEqual(stats["total"], 5)
        self.assertEqual(stats["matched"], 3)
        self.assertEqual(stats["corrected"], 2)

    def test_empty_stats(self):
        """Empty feedback loop should return zeroed stats."""
        fb = _FeedbackLoop()
        stats = fb.get_daily_stats("2099-01-01")
        self.assertEqual(stats["total"], 0)
        self.assertEqual(stats["matched"], 0)
        self.assertEqual(stats["corrected"], 0)


if __name__ == "__main__":
    unittest.main()
