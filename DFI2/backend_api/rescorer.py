"""Background flow rescorer — parameterized model/labels/skip.

Spawns scoring as a subprocess using system Python (which has ML libs).
Tracks progress via a shared JSON status file.
"""
import json
import logging
import os
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("dfi2.rescorer")

SCORE_SCRIPT = "/opt/dfi2/ml/score_norm_flows.py"
STATUS_FILE = "/tmp/norm_rescore/status.json"
SYSTEM_PYTHON = "/usr/bin/python3"
MODELS_DIR = "/opt/dfi2/ml/models"

_lock = threading.Lock()
_process: subprocess.Popen | None = None
_feature_cache: dict[str, int | None] = {}


def _read_status_file() -> dict:
    """Read the status JSON file written by the scoring subprocess."""
    try:
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE) as f:
                return json.load(f)
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def _get_unscored_count(model_name: str = "xgb_v6", labels: list[int] | None = None) -> int:
    """Quick CH query for unscored flow count with given params."""
    labels = labels or [5]
    labels_csv = ",".join(str(x) for x in labels)
    try:
        r = subprocess.run(
            ["clickhouse-client", "--query",
             f"SELECT count() FROM ("
             f"  SELECT DISTINCT l.flow_id FROM dfi.labels l"
             f"  LEFT ANTI JOIN dfi.model_predictions p"
             f"    ON p.flow_id = l.flow_id AND p.model_name = '{model_name}'"
             f"  WHERE l.label IN ({labels_csv})"
             f")"],
            capture_output=True, timeout=30
        )
        return int(r.stdout.decode().strip())
    except Exception:
        return -1


def _compute_fold_recall_precision(cm: list[list[int]]) -> tuple[float, float]:
    """Compute recall and precision from 2x2 confusion matrix [[TN,FP],[FN,TP]]."""
    if len(cm) != 2 or len(cm[0]) != 2:
        return 0.0, 0.0
    tn, fp = cm[0]
    fn, tp = cm[1]
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    return recall, precision


def list_model_registry() -> list[dict]:
    """Scan models directory and return rich metadata for each model.

    Includes both .json (XGB) and .pt (CNN) files, tracks symlinks as
    aliases, marks deployed models, and loads companion _metrics.json
    sidecars when available.
    """
    import re

    models_path = Path(MODELS_DIR)
    if not models_path.exists():
        return []

    # First pass: build a map of symlinks -> their real targets
    # symlink_name -> resolved target filename
    symlink_map: dict[str, str] = {}   # target_filename -> [alias_names]
    target_aliases: dict[str, list[str]] = {}
    for f in models_path.iterdir():
        if f.is_symlink():
            try:
                target = f.resolve()
                symlink_map[f.name] = target.name
                target_aliases.setdefault(target.name, []).append(f.stem)
            except (OSError, ValueError):
                pass

    result = []
    for f in sorted(models_path.iterdir()):
        try:
            # Skip metrics sidecars, symlinks, non-model files, and validation files
            if f.name.endswith("_metrics.json"):
                continue
            if f.name.endswith("_validation_latest.json"):
                continue
            if f.is_symlink():
                continue
            if f.suffix not in (".json", ".pt"):
                continue
            if not f.is_file():
                continue

            stat = f.stat()

            # Determine model type
            model_type = "cnn" if f.suffix == ".pt" else "xgb"

            # Extract timestamp from filename (pattern: YYYYMMDD_HHMMSS)
            ts_match = re.search(r"(\d{8}_\d{6})", f.stem)
            timestamp = ts_match.group(1) if ts_match else ""

            # Derive model name from filename (strip timestamp suffix)
            if ts_match:
                model_name = f.stem[:ts_match.start()].rstrip("_")
            else:
                model_name = f.stem

            # Check for aliases (symlinks pointing to this file)
            aliases = target_aliases.get(f.name, [])
            is_deployed = len(aliases) > 0

            entry: dict = {
                "filename": f.name,
                "model_name": model_name,
                "timestamp": timestamp,
                "model_type": model_type,
                "size_bytes": stat.st_size,
                "n_samples": 0,
                "n_features": 0,
                "n_folds": 0,
                "avg_accuracy": 0.0,
                "avg_f1": 0.0,
                "is_deployed": is_deployed,
                "aliases": sorted(aliases),
                "has_metrics": False,
            }

            # Load companion metrics file
            metrics_path = f.with_name(f.stem + "_metrics.json")
            if metrics_path.exists():
                try:
                    with open(metrics_path) as mf:
                        m = json.load(mf)
                    entry["has_metrics"] = True
                    entry["n_samples"] = m.get("n_samples", 0) or 0
                    entry["n_features"] = m.get("n_features", 0) or 0
                    # Override model_name from metrics if available
                    if m.get("model"):
                        entry["model_name"] = m["model"]

                    folds = m.get("folds", [])
                    entry["n_folds"] = len(folds)
                    if folds:
                        entry["avg_accuracy"] = sum(
                            fd.get("accuracy", 0) for fd in folds
                        ) / len(folds)
                        entry["avg_f1"] = sum(
                            fd.get("macro_f1", 0) for fd in folds
                        ) / len(folds)
                except Exception as exc:
                    log.warning("Failed to read metrics %s: %s", metrics_path, exc)

            result.append(entry)
        except Exception as exc:
            log.warning("Error scanning model %s: %s", f, exc)
            continue

    # Sort by timestamp descending (newest first), models without timestamp last
    result.sort(key=lambda e: e["timestamp"] or "00000000_000000", reverse=True)
    return result


def delete_model(filename: str) -> dict:
    """Delete a model file and its companion metrics file."""
    safe = Path(filename).name  # prevent path traversal
    model_path = Path(MODELS_DIR) / safe
    if not model_path.exists():
        return {"ok": False, "message": f"Model not found: {safe}"}
    metrics_path = model_path.with_name(model_path.stem + "_metrics.json")
    model_path.unlink()
    if metrics_path.exists():
        metrics_path.unlink()
    _feature_cache.pop(str(model_path), None)
    return {"ok": True, "message": f"Deleted {safe}"}


def list_models() -> list[dict]:
    """List available model files in MODELS_DIR with training metrics."""
    models_path = Path(MODELS_DIR)
    if not models_path.exists():
        return []
    result = []
    for f in sorted(models_path.glob("*.json")):
        if f.name.endswith("_metrics.json"):
            continue
        stat = f.stat()
        feat_count = _get_feature_count(str(f))
        entry = {
            "filename": f.name,
            "path": str(f),
            "size_bytes": stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "features": feat_count,
        }

        # Read companion metrics file
        metrics_path = f.with_name(f.stem + "_metrics.json")
        if metrics_path.exists():
            try:
                with open(metrics_path) as mf:
                    m = json.load(mf)
                entry["model_label"] = m.get("model")
                entry["n_samples"] = m.get("n_samples")
                entry["n_features"] = m.get("n_features")
                entry["best_iteration"] = m.get("best_iteration")
                params = m.get("params", {})
                entry["max_depth"] = params.get("max_depth")
                entry["learning_rate"] = params.get("learning_rate")
                entry["label_distribution"] = m.get("label_distribution")

                folds_raw = m.get("folds", [])
                folds = []
                recalls = []
                precisions = []
                for fd in folds_raw:
                    folds.append({
                        "fold": fd.get("fold", 0),
                        "val_logloss": fd.get("val_logloss", 0),
                        "accuracy": fd.get("accuracy", 0),
                        "macro_f1": fd.get("macro_f1", 0),
                        "weighted_f1": fd.get("weighted_f1", 0),
                        "confusion_matrix": fd.get("confusion_matrix", []),
                    })
                    cm = fd.get("confusion_matrix", [])
                    r, p = _compute_fold_recall_precision(cm)
                    recalls.append(r)
                    precisions.append(p)

                entry["folds"] = folds
                n = len(folds_raw)
                if n > 0:
                    entry["avg_accuracy"] = sum(fd.get("accuracy", 0) for fd in folds_raw) / n
                    entry["avg_macro_f1"] = sum(fd.get("macro_f1", 0) for fd in folds_raw) / n
                    entry["avg_recall"] = sum(recalls) / n
                    entry["avg_precision"] = sum(precisions) / n
            except Exception as exc:
                log.warning("Failed to read metrics %s: %s", metrics_path, exc)

        result.append(entry)
    return result


def _get_feature_count(model_path: str) -> int | None:
    """Get feature count from a booster, with caching (only caches successes)."""
    if model_path in _feature_cache:
        return _feature_cache[model_path]
    try:
        import xgboost as xgb
        booster = xgb.Booster()
        booster.load_model(model_path)
        count = len(booster.feature_names) if booster.feature_names else None
        if count is not None:
            _feature_cache[model_path] = count
        return count
    except Exception as exc:
        log.debug("Failed to load features from %s: %s", model_path, exc)
        return None


def get_status(model_name: str | None = None, labels: list[int] | None = None) -> dict:
    """Return current rescore status."""
    global _process

    sf = _read_status_file()

    # Check if subprocess is still running
    with _lock:
        if _process is not None:
            ret = _process.poll()
            if ret is not None:
                _process = None
                if sf.get("status") == "running":
                    sf["status"] = "failed" if ret != 0 else "completed"

    status = sf.get("status", "idle")
    result = {
        "status": status,
        "total": sf.get("total", 0),
        "scored": sf.get("scored", 0),
        "batch": sf.get("batch", 0),
        "attack_count": sf.get("attack_count", 0),
        "norm_count": sf.get("norm_count", 0),
        "started_at": sf.get("started_at"),
        "finished_at": sf.get("finished_at"),
        "elapsed_sec": sf.get("elapsed_sec", 0),
        "rate": sf.get("rate", 0),
        "error": sf.get("error"),
        "last_run_results": sf.get("last_run_results"),
        "config": sf.get("config"),
    }

    # Use params from status file config if not overridden
    q_model = model_name or (sf.get("config", {}) or {}).get("model_name", "xgb_v6")
    q_labels = labels or (sf.get("config", {}) or {}).get("labels", [5])

    if status in ("idle", "completed", "failed"):
        result["unscored_remaining"] = _get_unscored_count(q_model, q_labels)
    else:
        result["unscored_remaining"] = max(0, result["total"] - result["scored"])

    return result


def start_rescore(
    model_path: str = "/opt/dfi2/ml/models/xgb_20260302_154900.json",
    model_name: str = "xgb_v6",
    model_version: str = "rescore",
    labels: list[int] | None = None,
    skip_scored: bool = True,
) -> dict:
    """Start background rescore subprocess with given params."""
    global _process
    labels = labels or [5]

    with _lock:
        if _process is not None and _process.poll() is None:
            return {"ok": False, "message": "Rescore already running"}

        config = {
            "model_path": model_path,
            "model_name": model_name,
            "model_version": model_version,
            "labels": labels,
            "skip_scored": skip_scored,
        }

        # Write initial status
        os.makedirs(os.path.dirname(STATUS_FILE), exist_ok=True)
        with open(STATUS_FILE, "w") as f:
            json.dump({
                "status": "running",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "config": config,
            }, f)

        # Build CLI args
        cmd = [
            SYSTEM_PYTHON, SCORE_SCRIPT,
            "--model-path", model_path,
            "--model-name", model_name,
            "--model-version", model_version,
            "--labels", ",".join(str(x) for x in labels),
        ]
        if skip_scored:
            cmd.append("--skip-scored")
        else:
            cmd.append("--no-skip-scored")

        # Spawn subprocess
        log_file = "/tmp/norm_rescore/rescore.log"
        log_fh = open(log_file, "w")
        _process = subprocess.Popen(
            cmd,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            cwd="/tmp/norm_rescore",
        )
        log.info("Started rescore subprocess PID=%d cmd=%s", _process.pid, cmd)

    return {"ok": True, "message": f"Rescore started (PID {_process.pid})"}
