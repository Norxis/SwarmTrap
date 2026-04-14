"""Inference subsystem -- real-time XGBoost classification pipeline."""
from .accumulator import FeatureAccumulator
from .engine import XGBEngine, PredictionResult, LABELS
from .pipeline import InferencePipeline
from .feedback import FeedbackLoop
from .frequency import FrequencyTable
from .depth import suggest_depth

__all__ = [
    "FeatureAccumulator",
    "XGBEngine",
    "PredictionResult",
    "LABELS",
    "InferencePipeline",
    "FeedbackLoop",
    "FrequencyTable",
    "suggest_depth",
]
