"""Capture depth suggestion based on prediction and confidence.

Maps model predictions to capture depth levels:
  D1 = minimal capture (headers only, save resources)
  D2 = standard capture (headers + limited payload)
  D3 = full capture (complete payload for forensic analysis)
"""
from __future__ import annotations

# Label constants (matches engine.LABELS)
_BENIGN = 0
_RECON = 1
_BRUTEFORCE = 2
_EXPLOIT = 3
_COMPROMISE = 4


def suggest_depth(prediction: int, confidence: float) -> str:
    """Suggest capture depth based on prediction class and confidence.

    Rules (evaluated in priority order):
      - COMPROMISE (any confidence) -> D3 (full capture, forensic priority)
      - EXPLOIT >= 0.70            -> D3 (full capture)
      - BRUTEFORCE >= 0.85         -> D2 (standard)
      - RECON >= 0.90              -> D1 (minimal)
      - BENIGN >= 0.95             -> D1 (minimal)
      - Any < 0.70 (uncertain)     -> D2 (gather more data)
      - Default                    -> D2

    Args:
        prediction: Predicted class (0=BENIGN, 1=RECON, 2=BRUTEFORCE,
                    3=EXPLOIT, 4=COMPROMISE).
        confidence: Model confidence for the prediction (0.0-1.0).

    Returns:
        Depth string: "D1", "D2", or "D3".
    """
    # COMPROMISE always gets full capture
    if prediction == _COMPROMISE:
        return "D3"

    # EXPLOIT with reasonable confidence gets full capture
    if prediction == _EXPLOIT and confidence >= 0.70:
        return "D3"

    # Uncertain predictions get standard capture to gather more data
    if confidence < 0.70:
        return "D2"

    # BRUTEFORCE with good confidence gets standard capture
    if prediction == _BRUTEFORCE and confidence >= 0.85:
        return "D2"

    # RECON with high confidence gets minimal capture
    if prediction == _RECON and confidence >= 0.90:
        return "D1"

    # BENIGN with very high confidence gets minimal capture
    if prediction == _BENIGN and confidence >= 0.95:
        return "D1"

    # Default: standard capture
    return "D2"
