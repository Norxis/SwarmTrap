// ── Response wrappers ──
export interface ApiResponse {
  ok: boolean;
  request_id: string;
  message: string;
}

export interface BulkResponse extends ApiResponse {
  processed: number;
  skipped: number;
}

// ── Watchlist ──
export interface WatchlistEntry {
  ip: string;
  capture_depth: number;
  priority: number;
  group_id: string | null;
  sub_group_id: string | null;
  reason: string | null;
  source: string | null;
  expires_at_epoch: number | null;
  updated_at_epoch: number;
}

// ── Request bodies ──
export interface WatchlistUpsertRequest {
  ip: string;
  capture_depth: number;
  priority: number;
  reason: string;
  source?: string;
  actor?: string;
  expires_at?: string | null;
  group_id?: string | null;
  sub_group_id?: string | null;
}

export interface WatchlistDeleteRequest {
  ip: string;
  reason: string;
  actor?: string;
}

export interface BulkActionRequest {
  action: "upsert" | "delete";
  ip_list?: string[];
  campaign_id?: string | null;
  capture_depth?: number | null;
  priority?: number | null;
  reason: string;
  source?: string;
  actor?: string;
  expires_at?: string | null;
}

export interface AnnotateRequest {
  ip: string;
  note: string;
  tags?: string[];
  actor?: string;
}

export interface VMRebootRequest {
  reason?: string;
  actor?: string;
}

// ── Audit ──
export interface AuditRow {
  timestamp: number;
  ip: string;
  action: string;
  old_val: string;
  new_val: string;
  actor: string;
  reason: string;
  request_id: string;
  source: string;
}

// ── VMs ──
export interface VMStatus {
  vmid: number;
  name: string;
  lan_ip: string;
  pub_ip: string;
  os: string;
  services: string;
  status: string;
  cpu_pct: number;
  ram_used_mb: number;
  ram_total_mb: number;
  uptime_s: number;
  flows_24h: number;
  attackers_24h: number;
}

export interface VMEvent {
  ts: number;
  src_ip: string;
  event_type: string;
  event_detail: string;
  source_log: string;
}

// ── ML Dashboard ──
export interface ConfusionCell {
  actual: string;
  predicted: string;
  count: number;
}

export interface FeatureImportance {
  feature: string;
  importance: number;
}

export interface ScoringThroughput {
  hour: string;
  predictions: number;
  attacks: number;
}

export interface MlModelStats {
  model_name: string;
  version: string;
  trained_at: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  total_predictions_24h: number;
  attack_rate_24h: number;
  confusion_matrix: ConfusionCell[];
  feature_importance: FeatureImportance[];
  scoring_throughput: ScoringThroughput[];
  label_distribution: Record<string, number>;
}

export interface ModelRegistryEntry {
  filename: string;
  model_name: string;
  timestamp: string;
  model_type: string;
  size_bytes: number;
  n_samples: number;
  n_features: number;
  n_folds: number;
  avg_accuracy: number;
  avg_f1: number;
  is_deployed: boolean;
  aliases: string[];
  has_metrics: boolean;
}

export interface ModelFoldMetrics {
  fold: number;
  val_logloss: number;
  accuracy: number;
  macro_f1: number;
  weighted_f1: number;
  confusion_matrix: number[][];
}

export interface ModelInfo {
  filename: string;
  path: string;
  size_bytes: number;
  modified_at: string;
  features: number | null;
  model_label: string | null;
  n_samples: number | null;
  n_features: number | null;
  best_iteration: number | null;
  max_depth: number | null;
  learning_rate: number | null;
  label_distribution: Record<string, number> | null;
  folds: ModelFoldMetrics[] | null;
  avg_accuracy: number | null;
  avg_macro_f1: number | null;
  avg_recall: number | null;
  avg_precision: number | null;
}

export interface TrainRequest {
  model_type: "attack" | "recon";
  balanced: number;
  min_conf: number;
  hours: number;
  folds: number;
}

export interface TrainConfig {
  model_type: "attack" | "recon";
  balanced: number;
  min_conf: number;
  hours: number;
  folds: number;
  output_dir: string;
  nthread: number;
}

export interface TrainExportProgress {
  status: string;
  rows: number;
  estimated_rows: number | null;
  elapsed_sec: number;
  label_distribution: Record<string, number>;
}

export interface TrainFoldResult {
  fold: number;
  val_logloss: number;
  accuracy: number;
  macro_f1: number;
  recall: number;
  precision: number;
  confusion_matrix: number[][];
}

export interface TrainTrainProgress {
  status: string;
  current_fold: number;
  total_folds: number;
  folds_completed: TrainFoldResult[];
  elapsed_sec: number;
}

export interface TrainResult {
  model_path: string;
  metrics_path: string;
  n_samples: number;
  n_features: number;
  best_iteration: number;
  avg_accuracy: number;
  avg_macro_f1: number;
  avg_recall: number;
  avg_precision: number;
  train_elapsed_sec: number;
}

export interface TrainStatus {
  status: "idle" | "running" | "completed" | "failed";
  phase: string | null;
  started_at: string | null;
  config: TrainConfig | null;
  export: TrainExportProgress | null;
  train: TrainTrainProgress | null;
  result: TrainResult | null;
  error: string | null;
}

export interface RescoreRequest {
  model_path: string;
  model_name: string;
  model_version: string;
  labels: number[];
  skip_scored: boolean;
}

export interface RescoreConfig {
  model_path: string;
  model_name: string;
  model_version: string;
  labels: number[];
  skip_scored: boolean;
}

export interface NormRescoreLastRun {
  total: number;
  attack: number;
  norm: number;
  elapsed_sec: number;
  rate: number;
}

export interface NormRescoreStatus {
  status: "idle" | "running" | "completed" | "failed";
  total: number;
  scored: number;
  batch: number;
  attack_count: number;
  norm_count: number;
  unscored_remaining: number;
  started_at: string | null;
  finished_at: string | null;
  elapsed_sec: number;
  rate: number;
  error: string | null;
  last_run_results: NormRescoreLastRun | null;
  config: RescoreConfig | null;
}

// ── GOD Pipeline ────────────────────────────────────────────────────

export interface GodHealthStage {
  count_5min?: number;
  count_10min?: number;
  count_30min?: number;
  last_ts: number;
  ok: boolean;
}

export interface GodHealth {
  pipeline_status: "healthy" | "stale" | "dead";
  stages: {
    god1_scores: GodHealthStage;
    brain_judgments: GodHealthStage;
    god2_verdicts: GodHealthStage;
    profile_active: GodHealthStage;
  };
}

export interface GodVerdictGroupBreakdown {
  verdict_group: string;
  count: number;
}

export interface GodVerdictBreakdown {
  verdict: string;
  count: number;
}

export interface GodServiceSummaryItem {
  service_id: number;
  service_name: string;
  ip_count: number;
  with_evidence: number;
  total_events: number;
}

export interface GodOverview {
  total_ips: number;
  evidence_count: number;
  drop_count: number;
  capture_count: number;
  discrepancy_count: number;
  recent_drops: number;
  score_log_5min: number;
  verdict_group_breakdown: GodVerdictGroupBreakdown[];
  verdict_breakdown: GodVerdictBreakdown[];
  service_summary: GodServiceSummaryItem[];
}

export interface GodServiceLabel {
  service_id: number;
  service_name: string;
  service_class: number;
  class_name: string;
  label_confidence?: number;
  label_source?: string;
  evidence_mask?: number;
  event_count?: number;
  first_seen?: number;
  last_seen?: number;
}

export interface GodCatch {
  src_ip: string;
  verdict: string;
  verdict_group: string;
  updated_at: number;
  evidence_count: number;
  best_xgb_class: number;
  xgb_class_name: string;
  xgb_clean_ratio: number;
  total_flows: number;
  unique_ports: number;
  unique_dsts: number;
  services: number[];
  service_classes: number[];
  evidence: { event_type: string; source_program: string; ts: number }[];
  service_labels: GodServiceLabel[];
}

export interface GodReputationRow {
  src_ip: string;
  verdict: string;
  verdict_group: string;
  evidence_count: number;
  evidence_types: number;
  best_xgb_class: number;
  xgb_class_name: string;
  xgb_clean_ratio: number;
  total_flows: number;
  unique_ports: number;
  unique_dsts: number;
  services: number[];
  service_classes: number[];
  evidence_services: number[];
  first_seen: number;
  last_seen: number;
  updated_at: number;
}

export interface GodReputationResponse {
  total: number;
  items: GodReputationRow[];
}

export interface GodTimelinePoint {
  ts: number;
  xgb_class: number;
  xgb_class_name: string;
  xgb_confidence: number;
  dst_port: number;
  pkts_rev: number;
  vlan_id: number;
}

export interface GodEvidenceEvent {
  ts: number;
  event_type: string;
  source_program: string;
  event_detail: string;
}

export interface GodIpDetail {
  profile: GodReputationRow | null;
  timeline: GodTimelinePoint[];
  evidence: GodEvidenceEvent[];
  service_labels: GodServiceLabel[];
  geo?: { country?: string; country_code?: string; lat?: number; lng?: number };
}

export interface GodDropVerdict {
  src_ip: string;
  verdict: string;
  verdict_group: string;
  evidence_count: number;
  xgb_clean_ratio: number;
  total_flows: number;
  updated_at: number;
  verdict_expires: number;
}

export interface GodCaptureVerdict {
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  ip_proto: number;
  vlan_id: number;
  xgb_class: number;
  xgb_class_name: string;
  xgb_confidence: number;
  discrepancy_type: string;
  truth_label: string;
  service_id: number;
  service_name: string;
  service_class: number;
  class_name: string;
  capture_value_score: number;
  first_ts: number;
  last_ts: number;
  captured_at: number;
  pkts_fwd: number;
  pkts_rev: number;
  bytes_fwd: number;
  bytes_rev: number;
}

export interface GodVerdictsResponse {
  tab: string;
  total: number;
  items: GodDropVerdict[] | GodCaptureVerdict[];
}

export interface GodServiceClassDist {
  class_id: number;
  class_name: string;
  count: number;
}

export interface GodBudgetEntry {
  class_id: number;
  class_name: string;
  group_count: number;
  group_target: number;
}

export interface GodServiceDetail {
  service_id: number;
  service_name: string;
  total_ips: number;
  total_events: number;
  classes: GodServiceClassDist[];
  budgets: GodBudgetEntry[];
}

export interface GodEvidenceByProgram {
  source_program: string;
  event_count: number;
  unique_ips: number;
}

export interface GodServicesResponse {
  services: GodServiceDetail[];
  evidence_by_program: GodEvidenceByProgram[];
}

export interface GodD2Category {
  key: string;
  label: string;
  training_label: string;
  count: number;
  types: number;
}

export interface GodD2Summary {
  categories: GodD2Category[];
  totals: { attack: number; clean: number; excluded: number };
}

export interface GodReadinessCategory {
  key: string;
  label: string;
  count: number;
  ips: number;
}

export interface GodReadiness {
  source: string;
  total_attack: number;
  categories: GodReadinessCategory[];
}

export interface GodModelEntry {
  file: string;
  size_mb: number;
  timestamp: string;
  model_name: string;
  classes: string[];
  n_samples: number;
  n_features: number;
  accuracy: number;
  macro_f1: number;
  best_iteration: number;
  top_features: string[];
  deployed_on: string[];
}

export interface GodBudgetRow {
  service_id: number;
  service_name: string;
  service_class: number;
  class_name: string;
  group_count: number;
  group_target: number;
  group_complete: number;
  unique_actors: number;
  deficit: number;
}

export interface GodXgbClass {
  class_id: number;
  name: string;
  count: number;
  ips: number;
}

export interface GodTrainingResponse {
  total_captured: number;
  capture_limit: number;
  pct_complete: number;
  by_category: GodD2Summary;
  fiveclass_readiness: GodReadiness;
  fiveclass_by_xgb: GodXgbClass[];
  models: GodModelEntry[];
  service_budgets: GodBudgetRow[];
}

export interface GodMapAttacker {
  src_ip: string;
  xgb_class: number;
  xgb_class_name: string;
  flow_count: number;
  first_ts: number;
  last_ts: number;
  lat: number;
  lng: number;
  country: string;
  country_code: string;
}

export interface GodAllowlistEntry {
  src_ip: string;
  updated_at: number;
}

export interface TopCountry {
  country: string;
  country_code: string;
  attacks: number;
  unique_ips: number;
}
