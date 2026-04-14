"""Unit tests for the XGBoost inference pipeline."""
from __future__ import annotations

import unittest


# Label constants (matching inference engine -- binary v6+)
LABELS = {0: "NORM", 1: "ATTACK"}


class _MockXGBEngine:
    """Mock XGBoost engine for testing pipeline behavior."""

    def __init__(self, fixed_label: int = 0, fixed_confidence: float = 0.5):
        self._fixed_label = fixed_label
        self._fixed_confidence = fixed_confidence
        self.predict_count = 0

    def predict(self, features: list[float], feature_names: list[str] | None = None) -> dict:
        self.predict_count += 1
        return {
            "label": self._fixed_label,
            "label_name": LABELS.get(self._fixed_label, "UNKNOWN"),
            "confidence": self._fixed_confidence,
            "probabilities": {
                LABELS[i]: (self._fixed_confidence if i == self._fixed_label
                            else (1.0 - self._fixed_confidence))
                for i in range(2)
            },
        }


class _InferencePipeline:
    """Simplified inference pipeline for testing.

    Implements progressive inference at packet count thresholds
    and fast-path heuristics for obvious cases.
    """

    # Packet count thresholds for progressive inference
    THRESHOLDS = [5, 20, 50]
    ACCEPT_CONFIDENCE = 0.90

    def __init__(self, engine: _MockXGBEngine, config: object = None):
        self._engine = engine
        self._config = config
        self._results: dict[str, dict] = {}  # flow_id -> latest result
        self._accepted: set[str] = set()

    def on_packet(self, flow_id: str, pkt_count: int,
                  features: list[float], flow_meta: dict | None = None) -> dict | None:
        """Called for each packet. Returns prediction result if a threshold
        is reached or fast-path applies. Returns None otherwise.
        """
        # Already accepted at high confidence
        if flow_id in self._accepted:
            return self._results.get(flow_id)

        # Fast-path: SYN-only at 5 packets -> ATTACK
        if pkt_count == 5 and flow_meta:
            syn_only = flow_meta.get("syn_only", False)
            if syn_only:
                result = {
                    "flow_id": flow_id,
                    "label": 1,
                    "label_name": "ATTACK",
                    "confidence": 0.95,
                    "reason": "fast_path_syn_only",
                }
                self._results[flow_id] = result
                self._accepted.add(flow_id)
                return result

        # Progressive inference at thresholds
        if pkt_count in self.THRESHOLDS:
            pred = self._engine.predict(features)
            result = {
                "flow_id": flow_id,
                "label": pred["label"],
                "label_name": pred["label_name"],
                "confidence": pred["confidence"],
                "reason": f"progressive_at_{pkt_count}",
            }
            self._results[flow_id] = result

            # Accept if confidence is high enough
            if pred["confidence"] >= self.ACCEPT_CONFIDENCE:
                self._accepted.add(flow_id)

            return result

        return None

    def on_flow_end(self, flow_id: str, features: list[float]) -> dict:
        """Final inference when flow terminates."""
        if flow_id in self._accepted:
            return self._results[flow_id]

        pred = self._engine.predict(features)
        result = {
            "flow_id": flow_id,
            "label": pred["label"],
            "label_name": pred["label_name"],
            "confidence": pred["confidence"],
            "reason": "flow_end",
        }
        self._results[flow_id] = result
        self._accepted.add(flow_id)
        return result


class TestPipeline(unittest.TestCase):
    def test_fast_path_attack(self):
        """SYN-only at 5 packets should immediately classify as ATTACK."""
        engine = _MockXGBEngine(fixed_label=0, fixed_confidence=0.5)
        pipeline = _InferencePipeline(engine)

        features = [0.0] * 68
        flow_meta = {"syn_only": True}

        # Should not trigger at packets 1-4
        for i in range(1, 5):
            result = pipeline.on_packet("flow-1", i, features, flow_meta)
            self.assertIsNone(result)

        # At packet 5 with syn_only=True, fast path triggers
        result = pipeline.on_packet("flow-1", 5, features, flow_meta)
        self.assertIsNotNone(result)
        self.assertEqual(result["label"], 1)
        self.assertEqual(result["label_name"], "ATTACK")
        self.assertEqual(result["reason"], "fast_path_syn_only")
        self.assertGreaterEqual(result["confidence"], 0.90)

        # Engine should NOT have been called (fast path bypasses ML)
        self.assertEqual(engine.predict_count, 0)

    def test_progressive_inference(self):
        """Inference should run at 20, 50, and flow end thresholds."""
        engine = _MockXGBEngine(fixed_label=1, fixed_confidence=0.70)
        pipeline = _InferencePipeline(engine)

        features = [0.0] * 68

        # At packet 20
        result = pipeline.on_packet("flow-2", 20, features)
        self.assertIsNotNone(result)
        self.assertEqual(result["label"], 1)
        self.assertEqual(result["reason"], "progressive_at_20")

        # At packet 50
        result = pipeline.on_packet("flow-2", 50, features)
        self.assertIsNotNone(result)
        self.assertEqual(result["reason"], "progressive_at_50")

        # At flow end
        result = pipeline.on_flow_end("flow-2", features)
        self.assertIsNotNone(result)
        self.assertEqual(result["reason"], "flow_end")

        # Engine should have been called 3 times (20, 50, flow_end)
        self.assertEqual(engine.predict_count, 3)

    def test_threshold_accept(self):
        """Prediction with >= 0.90 confidence should be accepted and cached."""
        engine = _MockXGBEngine(fixed_label=1, fixed_confidence=0.95)
        pipeline = _InferencePipeline(engine)

        features = [0.0] * 68

        # At packet 20, high confidence -> accepted
        result = pipeline.on_packet("flow-3", 20, features)
        self.assertIsNotNone(result)
        self.assertEqual(result["label"], 1)
        self.assertGreaterEqual(result["confidence"], 0.90)

        # At packet 50, should return cached result (no new predict call)
        engine.predict_count = 0  # reset
        result = pipeline.on_packet("flow-3", 50, features)
        self.assertIsNotNone(result)
        self.assertEqual(engine.predict_count, 0, "Should not re-predict after acceptance")

    def test_below_threshold_not_accepted(self):
        """Low confidence should NOT accept — inference continues at next threshold."""
        engine = _MockXGBEngine(fixed_label=0, fixed_confidence=0.40)
        pipeline = _InferencePipeline(engine)

        features = [0.0] * 68

        # At packet 20, low confidence
        result = pipeline.on_packet("flow-4", 20, features)
        self.assertIsNotNone(result)
        self.assertLess(result["confidence"], 0.90)

        # At packet 50, should call engine again (not cached)
        result = pipeline.on_packet("flow-4", 50, features)
        self.assertIsNotNone(result)
        self.assertEqual(engine.predict_count, 2)


if __name__ == "__main__":
    unittest.main()
