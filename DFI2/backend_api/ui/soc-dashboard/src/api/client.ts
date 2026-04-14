const API_BASE = import.meta.env.DEV ? "" : "";

function getApiKey(): string | null {
  return localStorage.getItem("soc_api_key");
}

export function setApiKey(key: string) {
  localStorage.setItem("soc_api_key", key);
}

function getBasicAuth(): string | null {
  return localStorage.getItem("soc_basic_auth");
}

export function setBasicAuth(user: string, pass: string) {
  localStorage.setItem("soc_basic_auth", btoa(`${user}:${pass}`));
}

function authHeaders(write = false): Record<string, string> {
  const h: Record<string, string> = {};
  const key = getApiKey();
  const basic = getBasicAuth();
  if (key) h["X-API-Key"] = key;
  if (basic) h["Authorization"] = `Basic ${basic}`;
  if (write) {
    h["Content-Type"] = "application/json";
    h["Idempotency-Key"] = crypto.randomUUID();
  }
  return h;
}

export class ApiError extends Error {
  status: number;
  detail: string;
  constructor(status: number, detail: string) {
    super(`${status}: ${detail}`);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

export async function apiFetch<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { headers: authHeaders() });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new ApiError(res.status, text);
  }
  return res.json();
}

export async function apiPost<T>(
  path: string,
  body: unknown,
): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: authHeaders(true),
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new ApiError(res.status, text);
  }
  return res.json();
}

export async function apiDelete<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "DELETE",
    headers: authHeaders(true),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new ApiError(res.status, text);
  }
  return res.json();
}

export function apiDownloadUrl(path: string): string {
  const key = getApiKey();
  const qs = key ? `?api_key=${encodeURIComponent(key)}` : "";
  return `${API_BASE}${path}${qs}`;
}

export async function healthCheck(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/health`, { headers: authHeaders() });
    return res.ok;
  } catch {
    return false;
  }
}
