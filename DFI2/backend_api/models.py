from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, IPvAnyAddress


class WatchlistUpsertRequest(BaseModel):
    ip: IPvAnyAddress
    capture_depth: int = Field(ge=0, le=3)
    priority: int = Field(default=3, ge=1, le=3)
    reason: str = Field(min_length=1, max_length=512)
    source: str = Field(default="analyst", min_length=1, max_length=64)
    actor: str = Field(default="dashboard", min_length=1, max_length=128)
    expires_at: datetime | None = None
    group_id: str | None = None
    sub_group_id: str | None = None


class WatchlistDeleteRequest(BaseModel):
    ip: IPvAnyAddress
    reason: str = Field(min_length=1, max_length=512)
    actor: str = Field(default="dashboard", min_length=1, max_length=128)


class BulkActionRequest(BaseModel):
    action: Literal["upsert", "delete"]
    ip_list: list[IPvAnyAddress] = Field(default_factory=list)
    campaign_id: str | None = Field(default=None, min_length=1, max_length=128)
    capture_depth: int | None = Field(default=None, ge=0, le=3)
    priority: int | None = Field(default=None, ge=1, le=3)
    reason: str = Field(min_length=1, max_length=512)
    source: str = Field(default="analyst", min_length=1, max_length=64)
    actor: str = Field(default="dashboard", min_length=1, max_length=128)
    expires_at: datetime | None = None


class ApiResponse(BaseModel):
    ok: bool
    request_id: str
    message: str


class BulkResponse(BaseModel):
    ok: bool
    request_id: str
    message: str
    processed: int
    skipped: int


class WatchlistEntry(BaseModel):
    ip: str
    capture_depth: int
    priority: int
    group_id: str | None = None
    sub_group_id: str | None = None
    reason: str | None = None
    source: str | None = None
    expires_at_epoch: float | None = None
    updated_at_epoch: float


class AnnotateRequest(BaseModel):
    ip: IPvAnyAddress
    note: str = Field(min_length=1, max_length=2000)
    tags: list[str] = Field(default_factory=list)
    actor: str = Field(default="dashboard", min_length=1, max_length=128)


class AuditRow(BaseModel):
    timestamp: int = 0
    ip: str = ""
    action: str = ""
    old_val: str = ""
    new_val: str = ""
    actor: str = ""
    reason: str = ""
    request_id: str = ""
    source: str = ""


# --- VM models ---

class VMStatus(BaseModel):
    vmid: int
    name: str
    lan_ip: str
    pub_ip: str
    os: str
    services: str
    status: str = "unknown"
    cpu_pct: float = 0.0
    ram_used_mb: int = 0
    ram_total_mb: int = 0
    uptime_s: int = 0
    flows_24h: int = 0
    attackers_24h: int = 0


class VMEvent(BaseModel):
    ts: int
    src_ip: str
    event_type: str
    event_detail: str
    source_log: str


class VMRebootRequest(BaseModel):
    reason: str = "manual_reboot"
    actor: str = "backend-ui"


# --- ML models ---

class ConfusionCell(BaseModel):
    actual: str
    predicted: str
    count: int


class FeatureImportance(BaseModel):
    feature: str
    importance: float


class ScoringThroughput(BaseModel):
    hour: str
    predictions: int
    attacks: int


class MlModelStats(BaseModel):
    model_name: str
    version: str
    trained_at: str
    accuracy: float
    precision_score: float  # 'precision' conflicts with Pydantic
    recall: float
    f1: float
    total_predictions_24h: int
    attack_rate_24h: float
    confusion_matrix: list[ConfusionCell]
    feature_importance: list[FeatureImportance]
    scoring_throughput: list[ScoringThroughput]
    label_distribution: dict[str, int]


# --- Rescore models ---

class RescoreRequest(BaseModel):
    model_path: str = Field(default="/opt/dfi2/ml/models/xgb_20260302_154900.json")
    model_name: str = Field(default="xgb_v6", min_length=1, max_length=128)
    model_version: str = Field(default="rescore", min_length=1, max_length=128)
    labels: list[int] = Field(default=[5])
    skip_scored: bool = True


class RescoreConfig(BaseModel):
    model_path: str = ""
    model_name: str = ""
    model_version: str = ""
    labels: list[int] = Field(default_factory=list)
    skip_scored: bool = True


class NormRescoreLastRun(BaseModel):
    total: int = 0
    attack: int = 0
    norm: int = 0
    elapsed_sec: float = 0
    rate: float = 0


class NormRescoreStatus(BaseModel):
    status: str  # idle | running | completed | failed
    total: int = 0
    scored: int = 0
    batch: int = 0
    attack_count: int = 0
    norm_count: int = 0
    unscored_remaining: int = 0
    started_at: str | None = None
    finished_at: str | None = None
    elapsed_sec: float = 0
    rate: float = 0
    error: str | None = None
    last_run_results: NormRescoreLastRun | None = None
    config: RescoreConfig | None = None


# --- Training models ---

class TrainRequest(BaseModel):
    model_type: str = Field(default="attack", pattern=r"^(attack|recon)$")
    balanced: int = Field(default=500000, ge=0)
    min_conf: float = Field(default=0.5, ge=0.0, le=1.0)
    hours: int = Field(default=0, ge=0)
    folds: int = Field(default=5, ge=2, le=10)

class TrainConfig(BaseModel):
    model_type: str = "attack"
    balanced: int = 500000
    min_conf: float = 0.5
    hours: int = 0
    folds: int = 5
    output_dir: str = ""
    nthread: int = 80

class TrainExportProgress(BaseModel):
    status: str = "pending"
    rows: int = 0
    estimated_rows: int | None = None
    elapsed_sec: float = 0
    label_distribution: dict[str, int] = Field(default_factory=dict)

class TrainFoldResult(BaseModel):
    fold: int
    val_logloss: float = 0
    accuracy: float = 0
    macro_f1: float = 0
    recall: float = 0
    precision: float = 0
    confusion_matrix: list[list[int]] = Field(default_factory=list)

class TrainTrainProgress(BaseModel):
    status: str = "pending"
    current_fold: int = 0
    total_folds: int = 5
    folds_completed: list[TrainFoldResult] = Field(default_factory=list)
    elapsed_sec: float = 0

class TrainResult(BaseModel):
    model_path: str = ""
    metrics_path: str = ""
    n_samples: int = 0
    n_features: int = 0
    best_iteration: int = 0
    avg_accuracy: float = 0
    avg_macro_f1: float = 0
    avg_recall: float = 0
    avg_precision: float = 0
    train_elapsed_sec: float = 0

class TrainStatus(BaseModel):
    status: str  # idle | running | completed | failed
    phase: str | None = None
    started_at: str | None = None
    config: TrainConfig | None = None
    export: TrainExportProgress | None = None
    train: TrainTrainProgress | None = None
    result: TrainResult | None = None
    error: str | None = None

class ModelRegistryEntry(BaseModel):
    filename: str
    model_name: str = ""
    timestamp: str = ""
    model_type: str = ""  # "xgb" or "cnn"
    size_bytes: int = 0
    n_samples: int = 0
    n_features: int = 0
    n_folds: int = 0
    avg_accuracy: float = 0.0
    avg_f1: float = 0.0
    is_deployed: bool = False
    aliases: list[str] = Field(default_factory=list)
    has_metrics: bool = False


class ModelFoldMetrics(BaseModel):
    fold: int
    val_logloss: float = 0
    accuracy: float = 0
    macro_f1: float = 0
    weighted_f1: float = 0
    confusion_matrix: list[list[int]] = Field(default_factory=list)

class ModelInfo(BaseModel):
    filename: str
    path: str
    size_bytes: int
    modified_at: str
    features: int | None = None
    # From metrics file
    model_label: str | None = None
    n_samples: int | None = None
    n_features: int | None = None
    best_iteration: int | None = None
    max_depth: int | None = None
    learning_rate: float | None = None
    label_distribution: dict[str, int] | None = None
    folds: list[ModelFoldMetrics] | None = None
    avg_accuracy: float | None = None
    avg_macro_f1: float | None = None
    avg_recall: float | None = None
    avg_precision: float | None = None


# ---------------------------------------------------------------------------
# Attack Map models
# ---------------------------------------------------------------------------

class MapAttacker(BaseModel):
    src_ip: str
    label: int
    flow_count: int
    first_ts: int
    last_ts: int
    top_ports: list[int] = []
    target_count: int = 0
    country: str = "Unknown"
    country_code: str = "XX"
    lat: float = 0.0
    lng: float = 0.0


class MapEventsResponse(BaseModel):
    attackers: list[MapAttacker] = []
    honeypots: list[dict] = []
    total_attacks: int = 0
