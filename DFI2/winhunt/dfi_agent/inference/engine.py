"""XGBoost inference engine -- loads a trained model and runs predictions.

Graceful degradation: if xgboost is not installed, predict() returns None
and logs a warning once. This allows the agent to run without the model
for capture-only deployments.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("winhunt.inference.engine")

# Label mapping -- binary classifier (v6+)
LABELS: dict[int, str] = {
    0: "NORM",
    1: "ATTACK",
}

# Try importing xgboost at module level
try:
    import xgboost as xgb
    HAS_XGB = True
except ImportError:
    xgb = None  # type: ignore[assignment]
    HAS_XGB = False


@dataclass
class PredictionResult:
    """Result of a single XGBoost inference."""
    prediction: int
    label_name: str
    confidence: float
    probabilities: list[float]


class XGBEngine:
    """XGBoost inference engine.

    Loads a Booster model from a .json file and runs binary or multi-class
    classification with probability output. Handles feature name mapping
    between accumulator and model (fills missing features with NaN).
    """

    def __init__(self, model_path: str) -> None:
        """Load an XGBoost Booster from a JSON model file.

        Args:
            model_path: Path to .json model file (XGBoost Booster format).
        """
        self._booster: Any = None
        self._warned_no_xgb = False

        if not HAS_XGB:
            log.warning("xgboost not installed -- inference engine will return None")
            return

        self._booster = xgb.Booster()
        self._booster.load_model(model_path)
        log.info("XGBoost model loaded from %s", model_path)

        model_fnames = self._booster.feature_names
        log.info("model feature count: %d", len(model_fnames) if model_fnames else 0)

    def predict(
        self,
        vector: list[float | None],
        feature_names: list[str] | None = None,
    ) -> PredictionResult | None:
        """Run inference on a single feature vector.

        Maps accumulator features to model features by name. Missing model
        features are filled with NaN (XGBoost handles natively). Extra
        accumulator features not in the model are silently dropped.

        Args:
            vector: Feature values from accumulator.
            feature_names: Names corresponding to vector elements. If provided,
                features are mapped to the model's expected feature order.

        Returns:
            PredictionResult or None if model not loaded.
        """
        if self._booster is None:
            if not self._warned_no_xgb:
                log.warning("predict() called but no model loaded (xgboost missing?)")
                self._warned_no_xgb = True
            return None

        # Map accumulator features to model features (fill missing with NaN)
        model_fnames = self._booster.feature_names
        if feature_names is not None and model_fnames is not None:
            feat_map = dict(zip(feature_names, vector))
            clean_vector = [
                float(feat_map.get(f, float("nan")))
                if feat_map.get(f) is not None
                else float("nan")
                for f in model_fnames
            ]
        else:
            clean_vector = [float("nan") if v is None else float(v) for v in vector]

        try:
            dmatrix = xgb.DMatrix(
                data=[clean_vector],
                feature_names=model_fnames,
                missing=float("nan"),
                nthread=80,
            )
            raw = self._booster.predict(dmatrix)

            # binary:logistic returns P(class=1) as single scalar
            if raw.ndim == 1 and len(raw) == 1:
                prob_attack = float(raw[0])
                pred_class = 1 if prob_attack > 0.5 else 0
                confidence = prob_attack if pred_class == 1 else 1.0 - prob_attack
                prob_row = [1.0 - prob_attack, prob_attack]
            else:
                # Multi-class fallback
                prob_row = raw[0].tolist() if raw.ndim == 2 else raw.tolist()
                pred_class = int(max(range(len(prob_row)), key=lambda i: prob_row[i]))
                confidence = float(prob_row[pred_class])

            return PredictionResult(
                prediction=pred_class,
                label_name=LABELS.get(pred_class, "UNKNOWN"),
                confidence=confidence,
                probabilities=prob_row,
            )
        except Exception as exc:
            log.error("XGBoost prediction failed: %s", exc)
            return None

    @property
    def is_loaded(self) -> bool:
        """Whether a model is loaded and ready for inference."""
        return self._booster is not None
