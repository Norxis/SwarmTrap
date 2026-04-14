# Model Inventory

Trained models for SwarmTrap flow classification. Each model has a `.json` (XGBoost) or `.pt` (PyTorch CNN) weights file and a companion `_metrics.json` with cross-validation results, hyperparameters, and confusion matrices.

## Production Models

These are the current best models, deployed or ready for deployment.

### d2_binary_20260413.json
- **Type:** XGBoost binary (ATTACK vs CLEAN)
- **Objective:** `multi:softprob` (2-class)
- **Samples:** 7,059,764 (3.53M attack, 3.53M clean, balanced)
- **Features:** 57 (includes src_* source behavior features)
- **Best fold accuracy:** 99.53%
- **Best fold macro-F1:** 0.9953
- **Best iteration:** 7,615 rounds
- **GPU trained:** Yes (CUDA)
- **Notes:** Trained on D2 discrepancy capture data. The highest-accuracy binary model.

### xgb_5class_v2.json
- **Type:** XGBoost 5-class
- **Classes:** RECON, KNOCK, BRUTE, EXPLOIT, CLEAN
- **Samples:** 6,464,600 (1,292,920 per class, balanced)
- **Features:** 50 (no fingerprints or src_* -- dirty/clean captures lack those)
- **Best fold accuracy:** 87.2%
- **Best fold macro-F1:** 0.851
- **GPU trained:** Yes (CUDA)
- **Confusion notes:** BRUTE and EXPLOIT are the hardest to separate (shared traffic patterns during exploitation phase). RECON and CLEAN are near-perfect (>99%).

### cnn_3class_v1.pt / cnn_3class_v2.pt
- **Type:** PyTorch CNN 3-class
- **Classes:** RECON, ATTACK, CLEAN
- **Samples:** 12,597,324 (4.2M per class, balanced)
- **Static features:** 50
- **Best fold accuracy:** 96.5%
- **Best fold macro-F1:** 0.965
- **Best epoch count:** 25
- **Batch size:** 16,384
- **Learning rate:** 0.004
- **Notes:** v1 and v2 are sequential training runs. v2 is the latest. Architecture: 5 embedding layers (size_dir 24x12, flag 17x6, iat 9x6, rtt 10x6, entropy 7x4) -> multi-scale Conv1D (3/5/7) -> merge Conv1D -> AdaptiveMaxPool -> concat BN static -> FC head.

### xgb_recon_v3.json
- **Type:** XGBoost binary (RECON vs NORM)
- **Purpose:** Specialized reconnaissance detector for the inline recon scoring path in Hunter2.
- **Notes:** v2 and v3 are the same weights file. Used as `RECON_MODEL_PATH` in the capture engine.

## Evil Models (Attack vs Clean Binary)

Focused on separating truly malicious flows from clean baselines, without the RECON class.

### cnn_evil_v3.pt
- **Type:** PyTorch CNN binary (EVIL vs CLEAN)
- **Notes:** Latest evil CNN. Same architecture as CNN binary but trained on evil-specific prep data.

### evil_01.json / evil_20260306_181258.json
- **Type:** XGBoost binary (EVIL vs CLEAN)
- **Notes:** evil_01.json is the initial evil model. Subsequent dates are retraining iterations with different data prep (evil_02 through evil_07 series in the 20260310_* files).

### evil_20260314_230427.json
- **Type:** XGBoost binary (EVIL vs CLEAN)
- **Size:** 153 MB (largest evil model)
- **Notes:** Trained on the largest evil dataset. Later iterations with more training rounds.

## 3-Class XGBoost Models

### 3class_20260318_015015.json / 3class_20260318_034538.json
- **Type:** XGBoost 3-class (RECON vs ATTACK vs CLEAN)
- **Notes:** Large models (173 MB and 143 MB respectively). Two training runs on the same date with slightly different hyperparameters.

## 5-Class XGBoost Models

### 5class_20260318_000507.json
- **Type:** XGBoost 5-class
- **Notes:** First 5-class training run. Superseded by 5class_20260318_181733 (xgb_5class_v2).

### 5class_20260318_181733.json (= xgb_5class_v2.json)
- **Type:** XGBoost 5-class (RECON, KNOCK, BRUTE, EXPLOIT, CLEAN)
- **Notes:** Production 5-class model. See Production Models section above for details.

## CNN 3-Class Models

### cnn_3class_20260318_140327.pt / cnn_3class_20260319_022422.pt
- **Type:** PyTorch CNN 3-class
- **Notes:** Sequential training runs. The 20260319 version is the latest and matches cnn_3class_v2.pt.

## CNN Evil Models

### cnn_evil_20260307_122157.pt / cnn_evil_20260308_075514.pt
- **Type:** PyTorch CNN binary (EVIL vs CLEAN)
- **Notes:** Two sequential evil CNN training runs. cnn_evil_v3.pt is the latest.

## Early XGBoost Binary Models

### xgb_20260302_125111.json through xgb_20260305_173500.json
- **Type:** XGBoost binary (ATTACK vs NORM)
- **Notes:** Chronological progression of the binary classifier. Each iteration improved data prep, feature engineering, or hyperparameters. xgb_20260305_173500.json was the production binary model before d2_binary_20260413.json.

### xgb_recon_20260303_204416.json / xgb_recon_20260304_120444.json
- **Type:** XGBoost binary (RECON vs NORM)
- **Notes:** Reconnaissance detector iterations. xgb_recon_v3.json is the production version.

## Validation Artifacts

### recon_validation_latest.json
- **Type:** Validation report (not a model)
- **Purpose:** Latest recon model validation results for comparison.

## Model File Naming Convention

```
{type}_{YYYYMMDD}_{HHMMSS}.json        -- XGBoost model weights
{type}_{YYYYMMDD}_{HHMMSS}_metrics.json -- Training metrics, CV results, confusion matrices
{type}_{YYYYMMDD}_{HHMMSS}.pt          -- PyTorch CNN state dict
{type}_v{N}.json / .pt                 -- Symlink/copy of the Nth production version
```

Types: `xgb` (binary), `5class`, `3class`, `cnn_3class`, `cnn_evil`, `evil`, `xgb_recon`, `d2_binary`

## Metrics File Format

Every `_metrics.json` contains:

```json
{
  "model": "model_tag",
  "timestamp": "YYYYMMDD_HHMMSS",
  "classes": ["CLASS_0", "CLASS_1", ...],
  "n_samples": 7059764,
  "n_features": 57,
  "feature_names": ["dst_port", "ip_proto", ...],
  "params": { "objective": "...", "max_depth": 8, ... },
  "best_iteration": 7615,
  "folds": [
    {
      "fold": 1,
      "val_mlogloss": 0.0138,
      "accuracy": 0.9953,
      "macro_f1": 0.9953,
      "confusion_matrix": [[702420, 3336], [3332, 702865]]
    }
  ],
  "label_distribution": {"ATTACK": 3529882, "CLEAN": 3529882}
}
```
