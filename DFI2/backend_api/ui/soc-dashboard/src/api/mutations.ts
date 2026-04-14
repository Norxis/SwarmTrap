import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiPost, apiDelete } from "./client";
import type {
  ApiResponse,
  BulkResponse,
  WatchlistUpsertRequest,
  WatchlistDeleteRequest,
  BulkActionRequest,
  AnnotateRequest,
  RescoreRequest,
  TrainRequest,
  VMRebootRequest,
} from "./types";

export function useWatchlistUpsert() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: WatchlistUpsertRequest) =>
      apiPost<ApiResponse>("/watchlist/upsert", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["watchlist"] });
      qc.invalidateQueries({ queryKey: ["attackers"] });
      qc.invalidateQueries({ queryKey: ["overview"] });
    },
  });
}

export function useWatchlistDelete() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: WatchlistDeleteRequest) =>
      apiPost<ApiResponse>("/watchlist/delete", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["watchlist"] });
      qc.invalidateQueries({ queryKey: ["attackers"] });
    },
  });
}

export function useBulkAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: BulkActionRequest) =>
      apiPost<BulkResponse>("/action/bulk", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["watchlist"] });
      qc.invalidateQueries({ queryKey: ["attackers"] });
      qc.invalidateQueries({ queryKey: ["campaigns"] });
    },
  });
}

export function useAnnotate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AnnotateRequest) =>
      apiPost<ApiResponse>("/action/annotate", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["audit"] });
    },
  });
}

export function useDemoteQuiet() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => apiPost<BulkResponse>("/action/demote-quiet", {}),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["watchlist"] });
      qc.invalidateQueries({ queryKey: ["attackers"] });
    },
  });
}

export function useStartRescore() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RescoreRequest) =>
      apiPost<ApiResponse>("/action/ml/rescore", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["rescore-status"] });
    },
  });
}

/** @deprecated Use useStartRescore instead */
export function useStartNormRescore() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => apiPost<ApiResponse>("/action/ml/rescore-norm", {}),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["rescore-status"] });
    },
  });
}

export function useStartTraining() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: TrainRequest) =>
      apiPost<ApiResponse>("/action/ml/train", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["train-status"] });
    },
  });
}

export function useDeleteModel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (filename: string) =>
      apiDelete<ApiResponse>(`/action/ml/models/${encodeURIComponent(filename)}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ml-models"] });
    },
  });
}

export function useVMReboot() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      vmid,
      body,
    }: {
      vmid: number;
      body: VMRebootRequest;
    }) => apiPost<ApiResponse>(`/vms/${vmid}/reboot`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vms"] });
    },
  });
}
