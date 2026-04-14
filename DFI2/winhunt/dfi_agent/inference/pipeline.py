"""Progressive classification pipeline -- runs inference at packet thresholds.

Calls XGBEngine at ~5, ~20, ~50 packets and at flow end to progressively
refine predictions as more data becomes available.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from .accumulator import FEATURE_NAMES, FeatureAccumulator
from .engine import LABELS, PredictionResult, XGBEngine

log = logging.getLogger("winhunt.inference.pipeline")

# Packet thresholds for progressive inference
_THRESHOLD_FAST = 5
_THRESHOLD_FIRST = 20
_THRESHOLD_REFINED = 50

# Confidence thresholds
_CONF_ACCEPT = 0.90
_CONF_TENTATIVE = 0.70


class InferencePipeline:
    """Progressive classification pipeline.

    Creates per-flow FeatureAccumulators and triggers XGBoost inference
    at configurable packet thresholds. Stores predictions in the buffer
    when confidence meets minimum thresholds.
    """

    def __init__(
        self,
        engine: XGBEngine | None,
        config: Any,
        buffer: Any,
    ) -> None:
        """Initialize the inference pipeline.

        Args:
            engine: XGBEngine instance (or None if inference disabled).
            config: AgentConfig with inference settings.
            buffer: AgentBuffer for storing predictions.
        """
        self.engine = engine
        self.config = config
        self.buffer = buffer
        self._accumulators: dict[str, FeatureAccumulator] = {}
        self._prediction_counts: dict[str, int] = {}  # flow_id -> prediction_number

    def on_flow_update(self, flow_state: Any, pkt_count: int) -> None:
        """Called by FlowTable at packet thresholds.

        Progressive inference:
          ~5 pkts:  fast-path heuristic check
          ~20 pkts: first XGB inference
          ~50 pkts: re-inference with more data

        Args:
            flow_state: The FlowState object from flow_table.
            pkt_count: Current total packet count for this flow.
        """
        flow_id = flow_state.flow_id

        # Create or get accumulator
        if flow_id not in self._accumulators:
            self._accumulators[flow_id] = FeatureAccumulator(
                flow_id=flow_id,
                dst_port=flow_state.dst_port,
                ip_proto=flow_state.ip_proto,
                app_proto=flow_state.app_proto,
            )
            self._prediction_counts[flow_id] = 0

        acc = self._accumulators[flow_id]

        # Update timing from flow state
        acc.first_ts = flow_state.first_ts
        acc.last_ts = flow_state.last_ts

        # ~5 pkts: fast-path heuristic check
        if pkt_count == _THRESHOLD_FAST:
            self._fast_path_check(flow_state, acc)

        # ~20 pkts: first XGB inference
        elif pkt_count == _THRESHOLD_FIRST:
            self._run_inference(flow_id, acc, is_final=False)

        # ~50 pkts: refined inference
        elif pkt_count == _THRESHOLD_REFINED:
            self._run_inference(flow_id, acc, is_final=False)

    def on_flow_end(self, flow_state: Any) -> None:
        """Final inference at flow completion.

        Args:
            flow_state: The completed FlowState object.
        """
        flow_id = flow_state.flow_id
        acc = self._accumulators.get(flow_id)
        if acc is None:
            return

        # Update final timing
        acc.first_ts = flow_state.first_ts
        acc.last_ts = flow_state.last_ts

        self._run_inference(flow_id, acc, is_final=True)

        # Cleanup accumulator
        self._accumulators.pop(flow_id, None)
        self._prediction_counts.pop(flow_id, None)

    def get_accumulator(self, flow_id: str) -> FeatureAccumulator | None:
        """Return the FeatureAccumulator for a flow, or None if not tracked."""
        return self._accumulators.get(flow_id)

    def _fast_path_check(self, flow_state: Any, acc: FeatureAccumulator) -> None:
        """Fast-path heuristic at ~5 packets.

        Quick pattern matching before full model inference:
          - SYN-only (no SYN-ACK, no data) -> ATTACK
          - Connection to non-service port -> ATTACK
        """
        if self.engine is None:
            return

        flow_id = flow_state.flow_id
        prediction: int | None = None
        confidence: float = 0.95  # heuristic confidence

        # SYN-only: sent SYNs but no SYN-ACK reply and no data
        if (acc.syn_count >= 1
                and not acc._has_syn_ack
                and acc.n_payload_pkts == 0):
            prediction = 1  # ATTACK
            log.debug("fast-path: flow %s SYN-only -> ATTACK", flow_id[:12])

        # Connection to non-service port (unusual target)
        if prediction is None:
            honeypot_ports = self.config.honeypot_ports()
            if honeypot_ports and flow_state.dst_port not in honeypot_ports:
                prediction = 1  # ATTACK (port scan)
                confidence = 0.80
                log.debug("fast-path: flow %s non-service port %d -> ATTACK",
                          flow_id[:12], flow_state.dst_port)

        if prediction is not None:
            self._prediction_counts[flow_id] = self._prediction_counts.get(flow_id, 0) + 1
            self._store_prediction(
                flow_id=flow_id,
                prediction=prediction,
                confidence=confidence,
                is_final=False,
                prediction_number=self._prediction_counts[flow_id],
                source="fast_path",
            )

    def _run_inference(
        self,
        flow_id: str,
        acc: FeatureAccumulator,
        is_final: bool,
    ) -> None:
        """Run XGBoost inference and store if confidence meets threshold."""
        if self.engine is None or not self.engine.is_loaded:
            return

        vector = acc.to_vector()
        result = self.engine.predict(vector, feature_names=FEATURE_NAMES)
        if result is None:
            return

        # Check confidence thresholds
        min_conf = _CONF_TENTATIVE
        if result.confidence < min_conf and not is_final:
            log.debug("inference: flow %s conf=%.2f < %.2f (skipped)",
                      flow_id[:12], result.confidence, min_conf)
            return

        self._prediction_counts[flow_id] = self._prediction_counts.get(flow_id, 0) + 1

        # Determine status
        if result.confidence >= _CONF_ACCEPT:
            status = "accepted"
        elif result.confidence >= _CONF_TENTATIVE:
            status = "tentative"
        else:
            status = "uncertain"

        self._store_prediction(
            flow_id=flow_id,
            prediction=result.prediction,
            confidence=result.confidence,
            is_final=is_final,
            prediction_number=self._prediction_counts[flow_id],
            source="xgboost",
            probabilities=result.probabilities,
            status=status,
        )

        label = LABELS.get(result.prediction, "?")
        log.info(
            "inference: flow %s -> %s (conf=%.2f, %s, pred#%d%s)",
            flow_id[:12], label, result.confidence, status,
            self._prediction_counts[flow_id],
            " FINAL" if is_final else "",
        )

    def _store_prediction(
        self,
        flow_id: str,
        prediction: int,
        confidence: float,
        is_final: bool,
        prediction_number: int,
        source: str,
        probabilities: list[float] | None = None,
        status: str = "tentative",
    ) -> None:
        """Store prediction in the buffer events table as a prediction event."""
        label_name = LABELS.get(prediction, f"UNKNOWN_{prediction}")
        detail = {
            "flow_id": flow_id,
            "prediction": prediction,
            "label": label_name,
            "confidence": round(confidence, 4),
            "is_final": is_final,
            "prediction_number": prediction_number,
            "source": source,
            "status": status,
            "feature_completeness": round(
                self._accumulators[flow_id].confidence(), 3
            ) if flow_id in self._accumulators else None,
        }
        if probabilities:
            detail["probabilities"] = [round(p, 4) for p in probabilities]

        self.buffer.insert_event(
            ts=time.time(),
            vm_id=self.config.vm_id,
            source_ip=None,
            source_port=0,
            service="inference",
            event_type="prediction",
            evidence_bits=0,
            raw_event_id=None,
            raw_channel=None,
            detail=detail,
        )
