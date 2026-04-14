import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { apiFetch } from "./client";
import type {
  AuditRow,
  WatchlistEntry,
  VMStatus,
  VMEvent,
  MlModelStats,
  ModelInfo,
  ModelRegistryEntry,
  NormRescoreStatus,
  TrainStatus,
  GodHealth,
  GodOverview,
  GodCatch,
  GodReputationResponse,
  GodIpDetail,
  GodVerdictsResponse,
  GodServicesResponse,
  GodServiceDetail,
  GodTrainingResponse,
  GodMapAttacker,
  GodAllowlistEntry,
  TopCountry,
} from "./types";

// ── GOD Pipeline ────────────────────────────────────────────────────

export function useGodHealth() {
  return useQuery({
    queryKey: ["god-health"],
    queryFn: () => apiFetch<GodHealth>("/data/god/health"),
    refetchInterval: 15_000,
  });
}

export function useGodOverview() {
  return useQuery({
    queryKey: ["god-overview"],
    queryFn: () => apiFetch<GodOverview>("/data/god/overview"),
    refetchInterval: 30_000,
    placeholderData: keepPreviousData,
  });
}

export function useGodCatches(limit = 10) {
  return useQuery({
    queryKey: ["god-catches", limit],
    queryFn: () =>
      apiFetch<{ items: GodCatch[] }>(`/data/god/catches?limit=${limit}`),
    refetchInterval: 30_000,
  });
}

export function useGodReputation(params: {
  archetype?: number;
  group?: number;
  has_evidence?: number;
  limit?: number;
  offset?: number;
  sort?: string;
  order?: string;
}) {
  const sp = new URLSearchParams();
  if (params.archetype != null) sp.set("archetype", String(params.archetype));
  if (params.group != null) sp.set("group", String(params.group));
  if (params.has_evidence != null)
    sp.set("has_evidence", String(params.has_evidence));
  sp.set("limit", String(params.limit ?? 50));
  sp.set("offset", String(params.offset ?? 0));
  sp.set("sort", params.sort ?? "total_flows");
  sp.set("order", params.order ?? "desc");

  return useQuery({
    queryKey: ["god-reputation", sp.toString()],
    queryFn: () =>
      apiFetch<GodReputationResponse>(`/data/god/reputation?${sp}`),
    refetchInterval: 30_000,
    placeholderData: keepPreviousData,
  });
}

export function useGodIpDetail(ip: string) {
  return useQuery({
    queryKey: ["god-ip", ip],
    queryFn: () => apiFetch<GodIpDetail>(`/data/god/ip/${ip}`),
    enabled: !!ip,
  });
}

export function useGodVerdicts(params: {
  tab?: "drops" | "captures";
  limit?: number;
  offset?: number;
  d2_type?: string;
}) {
  const sp = new URLSearchParams();
  sp.set("tab", params.tab ?? "drops");
  sp.set("limit", String(params.limit ?? 50));
  sp.set("offset", String(params.offset ?? 0));
  if (params.d2_type) sp.set("d2_type", params.d2_type);

  return useQuery({
    queryKey: ["god-verdicts", sp.toString()],
    queryFn: () => apiFetch<GodVerdictsResponse>(`/data/god/verdicts?${sp}`),
    refetchInterval: 30_000,
    placeholderData: keepPreviousData,
  });
}

export function useGodServices() {
  return useQuery({
    queryKey: ["god-services"],
    queryFn: () => apiFetch<GodServicesResponse>("/data/god/services"),
    refetchInterval: 30_000,
  });
}

export function useGodServiceDetail(serviceId: number) {
  return useQuery({
    queryKey: ["god-service", serviceId],
    queryFn: () =>
      apiFetch<GodServiceDetail>(`/data/god/services/${serviceId}`),
    enabled: serviceId > 0,
  });
}

export function useGodTraining() {
  return useQuery({
    queryKey: ["god-training"],
    queryFn: () => apiFetch<GodTrainingResponse>("/data/god/training"),
    refetchInterval: 60_000,
  });
}

export function useGodMapEvents(hours = 1, limit = 500) {
  return useQuery({
    queryKey: ["god-map-events", hours, limit],
    queryFn: () =>
      apiFetch<{ events: GodMapAttacker[]; total: number }>(
        `/data/god/map/events?hours=${hours}&limit=${limit}`,
      ),
    refetchInterval: 30_000,
  });
}

export function useGodMapHeatmap(days = 7) {
  return useQuery({
    queryKey: ["god-map-heatmap", days],
    queryFn: () =>
      apiFetch<{ heatmap: Record<string, number> }>(
        `/data/god/map/heatmap?days=${days}`,
      ),
    refetchInterval: 60_000,
  });
}

export function useGodMapCountries(hours = 24, limit = 10) {
  return useQuery({
    queryKey: ["god-map-countries", hours, limit],
    queryFn: () =>
      apiFetch<{ countries: TopCountry[] }>(
        `/data/god/map/countries?hours=${hours}&limit=${limit}`,
      ),
    refetchInterval: 60_000,
  });
}

export function useGodAllowlist() {
  return useQuery({
    queryKey: ["god-allowlist"],
    queryFn: () =>
      apiFetch<{ items: GodAllowlistEntry[] }>("/data/god/allowlist"),
  });
}

// ── Kept endpoints (ML, VM, Audit, Watchlist) ───────────────────────

export function useAuditLog(limit = 200) {
  return useQuery({
    queryKey: ["audit", limit],
    queryFn: () => apiFetch<AuditRow[]>(`/data/audit?limit=${limit}`),
  });
}

export function useWatchlist(limit = 500) {
  return useQuery({
    queryKey: ["watchlist", limit],
    queryFn: () => apiFetch<WatchlistEntry[]>(`/watchlist?limit=${limit}`),
  });
}

export function useVMs() {
  return useQuery({
    queryKey: ["vms"],
    queryFn: () => apiFetch<VMStatus[]>("/vms"),
  });
}

export function useVMEvents(vmid: number) {
  return useQuery({
    queryKey: ["vm-events", vmid],
    queryFn: () => apiFetch<VMEvent[]>(`/vms/${vmid}/events`),
    enabled: vmid > 0,
  });
}

export function useMlStats(modelName = "xgb_v6") {
  return useQuery({
    queryKey: ["ml-stats", modelName],
    queryFn: () =>
      apiFetch<MlModelStats>(`/data/ml/stats?model_name=${modelName}`),
    staleTime: 60_000,
  });
}

export function useAvailableModels() {
  return useQuery({
    queryKey: ["ml-models"],
    queryFn: () => apiFetch<ModelInfo[]>("/data/ml/models"),
    staleTime: 60_000,
  });
}

export function useModelRegistry() {
  return useQuery({
    queryKey: ["model-registry"],
    queryFn: () => apiFetch<ModelRegistryEntry[]>("/data/ml/registry"),
    staleTime: 60_000,
  });
}

export function useRescoreStatus(
  enabled = true,
  modelName?: string,
  labels?: number[],
) {
  const params = new URLSearchParams();
  if (modelName) params.set("model_name", modelName);
  if (labels?.length) params.set("labels", labels.join(","));
  const qs = params.toString();
  return useQuery({
    queryKey: ["rescore-status", modelName, labels],
    queryFn: () =>
      apiFetch<NormRescoreStatus>(
        `/data/ml/rescore-status${qs ? `?${qs}` : ""}`,
      ),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "running" ? 3_000 : 30_000;
    },
    enabled,
  });
}

export function useTrainStatus(enabled = true) {
  return useQuery({
    queryKey: ["train-status"],
    queryFn: () => apiFetch<TrainStatus>("/data/ml/train-status"),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "running" ? 3_000 : 30_000;
    },
    enabled,
  });
}
