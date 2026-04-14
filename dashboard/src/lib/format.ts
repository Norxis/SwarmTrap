export function timeAgo(epoch: number): string {
  const diff = Math.max(0, Math.floor(Date.now() / 1000) - epoch);
  const d = Math.floor(diff / 86400);
  const h = Math.floor((diff % 86400) / 3600);
  const m = Math.floor((diff % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ago`;
  if (h > 0) return `${h}h ${m}m ago`;
  if (m > 0) return `${m}m ago`;
  return "just now";
}

export function fmtTs(epoch: number): string {
  return new Date(epoch * 1000).toLocaleString();
}

export function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`;
  return `${(b / 1073741824).toFixed(1)} GB`;
}

export function fmtNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

export function fmtUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export function depthColor(d: number): string {
  switch (d) {
    case 0: return "var(--color-depth-0)";
    case 1: return "var(--color-depth-1)";
    case 2: return "var(--color-depth-2)";
    case 3: return "var(--color-depth-3)";
    default: return "var(--color-muted)";
  }
}

export function depthLabel(d: number): string {
  return `D${d}`;
}

export function priorityLabel(p: number): string {
  return `P${p}`;
}

export function labelName(label: number | null): string {
  if (label === null) return "Unknown";
  switch (label) {
    case 0: return "NORM";
    case 1: return "RECON";
    case 2: return "KNOCK";
    case 3: return "BRUTE";
    case 4: return "EXPLOIT";
    case 5: return "NORM";
    default: return `L${label}`;
  }
}

export function cn(...classes: (string | false | undefined | null)[]): string {
  return classes.filter(Boolean).join(" ");
}

/** Convert 2-char ISO country code to flag emoji. Returns "" for invalid/unknown. */
export function countryFlag(code: string | null | undefined): string {
  if (!code || code.length !== 2 || code === "XX") return "";
  return String.fromCodePoint(
    ...([...code.toUpperCase()].map((c) => 0x1f1e6 - 65 + c.charCodeAt(0))),
  );
}
