"""Background model trainer — orchestrates proven export.py + train_xgb.py.

Runs export.py to extract training CSV from ClickHouse, then train_xgb.py
to train XGBoost model with GroupKFold CV. Parses stdout of both scripts
in real-time and writes /tmp/ml_train/status.json for the API to poll.
"""
import json
import logging
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timezone

log = logging.getLogger("dfi2.trainer")

EXPORT_SCRIPT = "/opt/dfi2/ml/export.py"
TRAIN_SCRIPT = "/opt/dfi2/ml/train_xgb.py"
STATUS_FILE = "/tmp/ml_train/status.json"
STATUS_DIR = "/tmp/ml_train"
CSV_PATH = "/tmp/ml_train/training_data.csv"
SYSTEM_PYTHON = "/usr/bin/python3"

_lock = threading.Lock()
_running = False


def _write_status(data: dict):
    """Atomically write status JSON."""
    tmp = STATUS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, STATUS_FILE)


def _read_status_file() -> dict:
    """Read the status JSON file."""
    try:
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE) as f:
                return json.load(f)
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def get_train_status() -> dict:
    """Return current training status."""
    sf = _read_status_file()
    status = sf.get("status", "idle")
    return {
        "status": status,
        "phase": sf.get("phase"),
        "started_at": sf.get("started_at"),
        "config": sf.get("config"),
        "export": sf.get("export"),
        "train": sf.get("train"),
        "result": sf.get("result"),
        "error": sf.get("error"),
    }


def _run_training(config: dict):
    """Background thread: run export.py then train_xgb.py."""
    global _running
    started_at = datetime.now(timezone.utc).isoformat()

    status = {
        "status": "running",
        "phase": "export",
        "started_at": started_at,
        "config": config,
        "export": {"status": "running", "rows": 0, "elapsed_sec": 0, "label_distribution": {}},
        "train": {"status": "pending", "current_fold": 0, "total_folds": config["folds"], "folds_completed": [], "elapsed_sec": 0},
        "result": None,
        "error": None,
    }
    _write_status(status)

    try:
        # --- Phase 1: Export ---
        export_start = time.time()
        is_recon = config.get("model_type") == "recon"
        if is_recon:
            export_cmd = [
                SYSTEM_PYTHON, EXPORT_SCRIPT, "recon",
                "--balanced", str(config["balanced"]),
                "-o", CSV_PATH,
            ]
        else:
            export_cmd = [
                SYSTEM_PYTHON, EXPORT_SCRIPT, "xgb",
                "--balanced", str(config["balanced"]),
                "--min-conf", str(config["min_conf"]),
                "--hours", str(config["hours"]),
                "-o", CSV_PATH,
            ]
        log.info("Starting export: %s", export_cmd)

        proc = subprocess.Popen(
            export_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=STATUS_DIR,
        )

        export_rows = 0
        label_dist = {}
        export_output = []

        for line in proc.stdout:
            line = line.rstrip()
            export_output.append(line)
            log.info("export.py: %s", line)

            # Parse: "Exported 2000000 rows to /tmp/ml_train/training_data.csv in 45.3s"
            m = re.match(r"Exported (\d+) rows to .+ in ([\d.]+)s", line)
            if m:
                export_rows = int(m.group(1))
                status["export"]["rows"] = export_rows
                status["export"]["elapsed_sec"] = float(m.group(2))

            # Parse: "Label distribution: {1: 500000, 2: 500000, 3: 500000, 5: 500000}"
            m2 = re.match(r"Label distribution: (.+)", line)
            if m2:
                try:
                    raw = m2.group(1).replace("'", '"')
                    label_dist = {str(k): v for k, v in json.loads(raw).items()}
                except Exception:
                    # Fallback: parse {1: 500000, 5: 500000} manually
                    pairs = re.findall(r"(\d+):\s*(\d+)", m2.group(1))
                    label_dist = {p[0]: int(p[1]) for p in pairs}
                status["export"]["label_distribution"] = label_dist

            _write_status(status)

        proc.wait()
        export_elapsed = time.time() - export_start

        if proc.returncode != 0:
            status["status"] = "failed"
            status["error"] = f"export.py failed (exit {proc.returncode}): {' '.join(export_output[-3:])}"
            status["export"]["status"] = "failed"
            status["export"]["elapsed_sec"] = export_elapsed
            _write_status(status)
            return

        status["export"]["status"] = "completed"
        status["export"]["elapsed_sec"] = export_elapsed
        if export_rows == 0 and os.path.exists(CSV_PATH):
            # Count rows from CSV if export didn't report
            with open(CSV_PATH) as f:
                export_rows = sum(1 for _ in f) - 1  # minus header
            status["export"]["rows"] = export_rows

        # --- Phase 2: Train ---
        status["phase"] = "train"
        status["train"]["status"] = "running"
        _write_status(status)

        train_start = time.time()
        train_cmd = [
            SYSTEM_PYTHON, TRAIN_SCRIPT, CSV_PATH,
            "--folds", str(config["folds"]),
            "-o", config.get("output_dir", "/opt/dfi2/ml/models"),
        ]
        if is_recon:
            train_cmd.append("--recon")
        log.info("Starting training: %s", train_cmd)

        proc2 = subprocess.Popen(
            train_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=STATUS_DIR,
        )

        model_path = None
        train_output = []

        for line in proc2.stdout:
            line = line.rstrip()
            train_output.append(line)

            # Parse fold results: "  Fold 1: val_logloss=0.012345  macro_f1=0.9912  acc=0.9945"
            fm = re.match(r"\s*Fold\s+(\d+):\s+val_logloss=([\d.]+)\s+macro_f1=([\d.]+)\s+acc=([\d.]+)", line)
            if fm:
                fold_num = int(fm.group(1))
                fold_result = {
                    "fold": fold_num,
                    "val_logloss": float(fm.group(2)),
                    "macro_f1": float(fm.group(3)),
                    "accuracy": float(fm.group(4)),
                }
                status["train"]["folds_completed"].append(fold_result)
                status["train"]["current_fold"] = fold_num
                status["train"]["elapsed_sec"] = time.time() - train_start
                log.info("Fold %d complete: logloss=%.6f f1=%.4f acc=%.4f",
                         fold_num, fold_result["val_logloss"], fold_result["macro_f1"], fold_result["accuracy"])
                _write_status(status)
                continue

            # Last line is model path: "/opt/dfi2/ml/models/xgb_20260303_154900.json"
            if line.startswith("/opt/dfi2/ml/models/"):
                model_path = line.strip()
                log.info("Model saved: %s", model_path)

            # Log XGBoost verbose_eval lines at debug level
            if line.strip():
                log.debug("train_xgb.py: %s", line)

        proc2.wait()
        train_elapsed = time.time() - train_start

        if proc2.returncode != 0:
            status["status"] = "failed"
            status["error"] = f"train_xgb.py failed (exit {proc2.returncode}): {' '.join(train_output[-3:])}"
            status["train"]["status"] = "failed"
            status["train"]["elapsed_sec"] = train_elapsed
            _write_status(status)
            return

        status["train"]["status"] = "completed"
        status["train"]["elapsed_sec"] = train_elapsed

        # --- Phase 3: Done — read metrics file ---
        status["phase"] = "done"

        if model_path:
            metrics_path = model_path.replace(".json", "_metrics.json")
            result = {
                "model_path": model_path,
                "metrics_path": metrics_path,
                "n_samples": export_rows,
                "train_elapsed_sec": train_elapsed,
            }

            # Read _metrics.json for detailed results
            try:
                if os.path.exists(metrics_path):
                    with open(metrics_path) as f:
                        metrics = json.load(f)
                    result["n_features"] = metrics.get("n_features", 0)
                    result["best_iteration"] = metrics.get("best_iteration", 0)
                    folds = metrics.get("folds", [])
                    if folds:
                        result["avg_accuracy"] = sum(f.get("accuracy", 0) for f in folds) / len(folds)
                        result["avg_macro_f1"] = sum(f.get("macro_f1", 0) for f in folds) / len(folds)
            except Exception as e:
                log.warning("Failed to read metrics file: %s", e)

            status["result"] = result

        status["status"] = "completed"
        _write_status(status)
        log.info("Training completed: %s", model_path)

        # Clean up CSV
        try:
            if os.path.exists(CSV_PATH):
                os.remove(CSV_PATH)
                log.info("Cleaned up %s", CSV_PATH)
        except OSError as e:
            log.warning("Failed to clean up CSV: %s", e)

    except Exception as exc:
        log.exception("Training thread error")
        status["status"] = "failed"
        status["error"] = str(exc)
        _write_status(status)
    finally:
        with _lock:
            global _running
            _running = False


def start_training(
    model_type: str = "attack",
    balanced: int = 500000,
    min_conf: float = 0.5,
    hours: int = 0,
    folds: int = 5,
    output_dir: str = "/opt/dfi2/ml/models",
    nthread: int = 80,
) -> dict:
    """Start background training thread."""
    global _running

    with _lock:
        if _running:
            return {"ok": False, "message": "Training already running"}

        config = {
            "model_type": model_type,
            "balanced": balanced,
            "min_conf": min_conf,
            "hours": hours,
            "folds": folds,
            "output_dir": output_dir,
            "nthread": nthread,
        }

        os.makedirs(STATUS_DIR, exist_ok=True)
        _running = True

    t = threading.Thread(target=_run_training, args=(config,), daemon=True)
    t.start()
    log.info("Started training thread config=%s", config)

    return {"ok": True, "message": "Training started"}
