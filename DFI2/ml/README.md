# ML Pipeline

This directory contains the full machine learning pipeline for SwarmTrap: exporting training data from ClickHouse, preparing balanced datasets, training XGBoost and CNN models, scoring flows in batch, and higher-level classifiers (session rules, conversation assembler, cluster labeler).

## Pipeline Overview

```
ClickHouse (dfi, dfi_dirty, dfi_clean)
        |
  1. EXPORT  (export.py, export_chunks.py, export_d2.py, export_sessions.py)
        |    Raw CSV/Parquet dumps from CH flows + source_stats + labels
        v
  2. PREP    (prep_5class_v2.py, prep_cnn_3class.py, prep_d2.py, ...)
        |    Balance classes, cast types, expand CNN arrays, output parquet
        v
  3. TRAIN   (train_xgb.py, train_5class.py, train_cnn.py, train_cnn_3class.py, ...)
        |    GroupKFold CV, early stopping, GPU support, save model + metrics
        v
  4. SCORE   (score.py, score_3class.py, score_pv1_oneshot.py, ...)
        |    Batch inference: load model, fetch unscored flows, write predictions
        v
  5. DEPLOY  Copy model .json/.pt to sensor, update XGB_MODEL_PATH env var
```

## Model Types

### XGBoost Binary (ATTACK vs NORM)
- **Training script:** `train_xgb.py`
- **Features:** 75 XGB features (protocol, volume, timing, size shape, TCP behavior, payload content, fingerprints, source behavior)
- **Objective:** `binary:logistic`
- **Output:** `.json` model file
- **Best result:** 99.53% accuracy (d2_binary_20260413, 7M samples)

### XGBoost 5-Class
- **Training script:** `train_5class.py`
- **Classes:** RECON (0), KNOCK (1), BRUTE (2), EXPLOIT (3), CLEAN (4)
- **Features:** 50 features (no fingerprints or source_stats -- dirty/clean captures lack those)
- **Objective:** `multi:softprob`
- **Output:** `.json` model file
- **Best result:** 85.2% accuracy, 0.845 macro-F1 (5class_v2, 6.5M balanced samples)

### CNN Binary (ATTACK vs NORM)
- **Training script:** `train_cnn.py`
- **Input:** 5 packet sequence channels (128 tokens each) + 42 static scalar features
- **Architecture:** 5 learned embeddings -> multi-scale 1D convolutions (kernel 3/5/7) -> merge conv -> adaptive max pool -> concat with BN static features -> FC head
- **Output:** `.pt` state dict

### CNN 3-Class
- **Training script:** `train_cnn_3class.py`
- **Classes:** RECON (0), ATTACK (1), CLEAN (2)
- **Input:** Same architecture as CNN binary but with 3-class output
- **Best result:** 95.6% accuracy, 0.956 macro-F1 (cnn_3class_v2, 12.6M samples)

### XGBoost Evil (EVIL vs CLEAN)
- **Training script:** `train_xgb.py --evil`
- **Purpose:** Binary classifier focused on separating truly malicious flows from clean baselines

### XGBoost Recon (RECON vs NORM)
- **Training script:** `train_xgb.py --recon`
- **Purpose:** Specialized reconnaissance detector for the inline recon scoring path

## Key Scripts

### Export Scripts

| Script | Purpose |
|--------|---------|
| `export.py` | Primary export tool. Subcommands: `flows`, `labels`, `source-stats`, `all`. Exports raw CSV from any database (dfi, dfi_dirty, dfi_clean). Supports D2-only filtering, labeled-only export, label code filtering. Uses `clickhouse-client` subprocess for streaming. |
| `export_chunks.py` | Chunked export for large datasets that would OOM in a single query. |
| `export_d2.py` | Specialized export for D2 (discrepancy capture) data from `ip_capture_d2`. |
| `export_sessions.py` | Export session-level aggregated features from `session_stats`. |
| `export_conversations.py` | Export conversation-level features from the conversations table. |

### Data Preparation Scripts

| Script | Purpose |
|--------|---------|
| `prep_5class_v2.py` | Prepares 5-class XGB training data. Loads per-class CSVs (recon, knock, brute, exploit, clean), filters ingress-only + all protocols, balances to smallest class size, outputs parquet. Uses Polars for speed. |
| `prep_cnn_3class.py` | Prepares CNN 3-class training data. Similar to 5class but groups knock+brute+exploit into ATTACK, expands CNN packet arrays into 640 flat columns (5 channels x 128 positions). |
| `prep_cnn_3class_fast.py` | Optimized CNN prep using Polars vectorized array expansion. |
| `prep_cnn_3class_v2.py` | Updated CNN prep for the combined 722-column dataset format. |
| `prep_d2.py` | Prepares D2 discrepancy capture data for XGB training. |
| `prep_d2_cnn.py` | Prepares D2 discrepancy capture data for CNN training. |
| `prep_xgb_v7.py` | Legacy 75-feature XGB data prep (combined dataset format). |
| `prep_conversation_v1.py` | Prepares conversation-level training data. |
| `prep_session_v1.py` | Prepares session-level training data. |
| `prep_evidence_01.py` | Prepares evidence-enriched training data. |
| `prep_evil_01.py`, `prep_evil_02.py` | Prepares EVIL vs CLEAN binary training data. |
| `prep_3class_tcp.py` | Prepares 3-class TCP-only data. |
| `prep_cnn_evil_01.py` through `prep_cnn_evil_03.py` | CNN Evil model data prep iterations. |

### Training Scripts

| Script | Purpose |
|--------|---------|
| `train_xgb.py` | XGBoost binary trainer. GroupKFold cross-validation on actor_id, early stopping, label_confidence weighting. Supports `--recon`, `--evil`, `--evidence` modes, GPU via `--gpu`, and `--scale-pos-weight`. |
| `train_5class.py` | XGBoost 5-class multi-class trainer (`multi:softprob`). Same CV/early-stop pattern. |
| `train_cnn.py` | CNN binary trainer. Manual batching with pinned CPU tensors and non-blocking GPU transfer. Mixed precision (AMP) on CUDA. ReduceLROnPlateau scheduler. |
| `train_cnn_3class.py` | CNN 3-class trainer. Handles both pre-expanded columns and raw array expansion via Polars. |
| `train_d2_xgb.py` | XGBoost trainer for D2 discrepancy capture data. |
| `train_d2_cnn.py` | CNN trainer for D2 discrepancy capture data. |
| `train_3class.py` | XGBoost 3-class trainer (RECON/ATTACK/CLEAN). |
| `train_xgb_exploit.py` | Specialized exploit-focused XGBoost trainer. |

### Scoring Scripts

| Script | Purpose |
|--------|---------|
| `score.py` | Batch XGBoost and CNN scorer. Finds unscored flows via ANTI JOIN, fetches features in batches (200K), scores, writes predictions to `model_predictions_buffer`. Includes evidence mismatch report. |
| `score_3class.py` | 3-class batch scoring. |
| `score_pv1_oneshot.py` | One-shot scoring run against PV1 ClickHouse. |
| `score_pv1_cnn_oneshot.py` | One-shot CNN scoring against PV1. |
| `score_norm_flows.py` | Score flows in the norm (clean) database. |
| `score_dirty_evidence.py` | Score dirty flows with evidence enrichment. |
| `score_sessions.py` | Score session-level features. |

### Higher-Level Classifiers

| Script | Purpose |
|--------|---------|
| `session_rules.py` | Kill-chain stage classifier using threshold rules (no ML model). Detects RECON (port scanning), BRUTE (auth attempts), EXPLOIT (interactive sessions), and C2 (beacon patterns) from session-level aggregates. Runs as PV1 cron every 5 minutes. Promotes high-confidence sources to the SQLite watchlist. |
| `conversation_assembler.py` | Groups flows into multi-turn conversations by src_ip with 30-minute gap detection. Computes 42 static conversation features (scale, rhythm, volume, escalation, service targeting, model consensus, actor context) and 12-channel per-turn tokens. Writes to `dfi.conversations`, `dfi.conversation_turns`, and `dfi.conversation_labels`. Assigns 6-class behavioral archetypes: COMMODITY_BOT, COORDINATED_CAMPAIGN, HUMAN_OPERATOR, RESEARCH_BENIGN, UNKNOWN, CLEAN_BASELINE. |
| `conversation_cluster_labeler.py` | Enriches conversation labels via temporal clustering (Tier 3: COMMODITY_BOT confidence uplift when many IPs show same pattern) and reverse DNS lookup (Tier 2: RESEARCH_BENIGN for known scanner organizations like Shodan, Censys, Shadowserver). |
| `ip_reputation_builder.py` | Builds the central `ip_reputation` table from evidence events, model predictions, and behavioral analysis. Computes 4-factor capture scoring (reputation, service, direction, novelty). |
| `service_label_mapper.py` | Maps service-level labels to flow-level classifications. |

### Utility Scripts

| Script | Purpose |
|--------|---------|
| `bench_score.py` | Benchmark scoring throughput. |
| `compare_dirty.py` | Compare dirty traffic across different captures. |
| `compare_models_dirty.py` | Compare model performance on dirty traffic. |
| `test_models.py` | Model testing and validation utilities. |
| `refresh_standard_norm.py` | Refresh the standard norm dataset. |
| `xgb_classification_listener.py` | Real-time classification event listener. |

## How to Train a New Model

### 1. Export Data

On PV1 (where ClickHouse runs):

```bash
# Export attack flows (labeled)
python3 export.py flows --db dfi --labeled -o /tmp/attack.csv

# Export clean flows
python3 export.py flows --db dfi_clean -o /tmp/clean.csv

# Export dirty flows
python3 export.py flows --db dfi_dirty -o /tmp/dirty.csv

# Export source_stats for src_* features
python3 export.py source-stats --db dfi -o /tmp/src_stats.csv

# Or export everything at once
python3 export.py all --db dfi -o /tmp/dfi_export/
```

### 2. Prepare Training Data

On the Test server (GPU):

```bash
# 5-class XGB
python3 prep_5class_v2.py /nvme0n1-disk/ml/data \
    -o /nvme0n1-disk/ml/data/training_5class_v2.parquet

# CNN 3-class
python3 prep_cnn_3class.py /nvme0n1-disk/ml/data \
    -o /nvme0n1-disk/ml/data/cnn_3class.parquet
```

The prep scripts handle:
- Loading per-class CSVs with `\N` null handling
- Casting all feature columns to Float64 (prevents concat type mismatches)
- Renaming alternate CNN array column names to standard form
- Filtering by VLAN (ingress only, excludes VLAN 101 egress)
- Balancing classes to the smallest class size
- Expanding CNN array strings (`[1,2,3,...]`) into 640 flat Int8 columns
- Adding `label` and `label_confidence` columns
- Shuffling and outputting Parquet

### 3. Train

```bash
# XGBoost binary
python3 train_xgb.py training_data.parquet --folds 5 --gpu -o models/

# XGBoost 5-class
python3 train_5class.py training_5class_v2.parquet --folds 5 --gpu -o models/

# CNN 3-class
python3 train_cnn_3class.py cnn_3class.parquet \
    --epochs 50 --batch-size 16384 --folds 5 -o models/

# CNN binary
python3 train_cnn.py training_data.parquet \
    --epochs 50 --batch-size 512 --folds 5 -o models/
```

All training scripts:
- Use `GroupKFold` on `actor_id` to prevent data leakage (same attacker never in both train and validation)
- Apply `label_confidence` as sample weights
- Support `--gpu` for CUDA acceleration
- Save both the model (`.json` or `.pt`) and metrics (`.json` with per-fold results, confusion matrices, feature importance)
- Retrain final model on all data using best fold's iteration count

### 4. Score Existing Flows

```bash
# XGBoost batch scoring
python3 score.py xgb models/xgb_20260305_173500.json

# CNN batch scoring
python3 score.py cnn models/cnn_3class_v2.pt

# Score only recent flows
python3 score.py xgb models/xgb_latest.json --hours 24
```

### 5. Deploy

Copy the model file to the sensor host and update the environment:

```bash
scp models/xgb_latest.json sensor:/opt/dfi2/ml/models/
# Update XGB_MODEL_PATH in /etc/dfi-hunter/env2
# Restart the capture service
```

## Data Requirements

- **Minimum rows per class:** ~100K for XGB, ~500K for CNN
- **Feature columns:** 75 for XGB (full), 50 for 5-class (no fingerprints/src_*), 42 static for CNN
- **CNN sequence columns:** 5 channels x 128 positions = 640 Int8 columns (expanded from arrays)
- **Required metadata:** `actor_id` (for GroupKFold), `label`, `label_confidence`
- **Label encoding:** XGB binary uses label 5=NORM mapped to 0, labels 1/2/3=ATTACK mapped to 1. 5-class uses 0-4 directly.

## The `models/` Subdirectory

See [models/README.md](models/README.md) for a full inventory of trained models with descriptions and benchmark results.

## Dependencies

- `xgboost` -- Gradient boosted trees
- `torch` -- CNN training and inference
- `pandas` -- Data loading (pyarrow engine)
- `polars` -- Fast data prep (array expansion, CSV loading)
- `numpy` -- Array operations
- `scikit-learn` -- GroupKFold, classification_report, confusion_matrix
- `clickhouse-driver` -- ClickHouse native protocol (for scoring and session_rules)
- `dnspython` -- Reverse DNS lookups (conversation_cluster_labeler)
