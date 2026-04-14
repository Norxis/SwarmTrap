import { useState } from "react";
import { useGodVerdicts } from "../api/hooks";
import type { GodDropVerdict, GodCaptureVerdict } from "../api/types";
import { Badge, IpLink, Pagination } from "../components";
import { PageLoading, ErrorDisplay } from "../components/LoadingSkeleton";
import { timeAgo } from "../lib/format";

type Tab = "drops" | "captures";

const PAGE_SIZE = 50;

const D2_TYPES = ["All", "ATK", "FP", "RB", "BAL", "CLN-EGR", "CLN-ING"] as const;

function verdictVariant(verdict: string): string {
  if (verdict === "DROP") return "danger";
  if (verdict === "CAPTURE") return "accent";
  return "muted";
}

function verdictGroupVariant(group: string): string {
  if (group.startsWith("DIS_")) return "warn";
  if (group.endsWith("_EVD")) return "warn";
  if (group.startsWith("CLN")) return "ok";
  if (group.startsWith("RB")) return "muted";
  return "muted";
}

function d2TypeVariant(type: string): string {
  switch (type) {
    case "ATK":
      return "danger";
    case "FP":
      return "warn";
    case "RB":
      return "muted";
    case "BAL":
      return "accent";
    case "CLN-EGR":
    case "CLN-ING":
      return "ok";
    default:
      return "muted";
  }
}

function DropsTable({ items }: { items: GodDropVerdict[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-border text-muted text-left">
            <th className="py-2 px-3 font-medium">IP</th>
            <th className="py-2 px-3 font-medium">Verdict</th>
            <th className="py-2 px-3 font-medium">Verdict Group</th>
            <th className="py-2 px-3 font-medium">Evidence</th>
            <th className="py-2 px-3 font-medium">Clean Ratio</th>
            <th className="py-2 px-3 font-medium">Flows</th>
            <th className="py-2 px-3 font-medium">Expires</th>
            <th className="py-2 px-3 font-medium">When</th>
          </tr>
        </thead>
        <tbody>
          {items.map((row) => (
            <tr
              key={row.src_ip}
              className="border-b border-border/50 hover:bg-card/60"
            >
              <td className="py-2 px-3">
                <IpLink ip={row.src_ip} />
              </td>
              <td className="py-2 px-3">
                <Badge variant={verdictVariant(row.verdict ?? "")}>
                  {row.verdict}
                </Badge>
              </td>
              <td className="py-2 px-3">
                <Badge variant={verdictGroupVariant(row.verdict_group ?? "")}>
                  {row.verdict_group}
                </Badge>
              </td>
              <td className="py-2 px-3 text-center">
                {(row.evidence_count ?? 0) > 0 ? (
                  <span className="text-ok font-bold">{row.evidence_count}</span>
                ) : (
                  <span className="text-muted">--</span>
                )}
              </td>
              <td className="py-2 px-3 font-mono">
                {((row.xgb_clean_ratio ?? 0) * 100).toFixed(0)}%
              </td>
              <td className="py-2 px-3 font-mono">
                {row.total_flows.toLocaleString()}
              </td>
              <td className="py-2 px-3 text-muted whitespace-nowrap">
                {row.verdict_expires ? timeAgo(row.verdict_expires) : "--"}
              </td>
              <td className="py-2 px-3 text-muted whitespace-nowrap">
                {timeAgo(row.updated_at)}
              </td>
            </tr>
          ))}
          {items.length === 0 && (
            <tr>
              <td colSpan={8} className="py-8 text-center text-muted">
                No drop verdicts found
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function CapturesTable({ items }: { items: GodCaptureVerdict[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-border text-muted text-left">
            <th className="py-2 px-3 font-medium">IP</th>
            <th className="py-2 px-3 font-medium">Type</th>
            <th className="py-2 px-3 font-medium">Service</th>
            <th className="py-2 px-3 font-medium">Class</th>
            <th className="py-2 px-3 font-medium">XGB</th>
            <th className="py-2 px-3 font-medium">Pkts</th>
            <th className="py-2 px-3 font-medium">Captured</th>
          </tr>
        </thead>
        <tbody>
          {items.map((row, i) => (
            <tr
              key={`${row.src_ip}-${row.discrepancy_type}-${row.service_id}-${i}`}
              className="border-b border-border/50 hover:bg-card/60"
            >
              <td className="py-2 px-3">
                <IpLink ip={row.src_ip} />
              </td>
              <td className="py-2 px-3">
                <Badge variant={d2TypeVariant(row.discrepancy_type)}>
                  {row.discrepancy_type}
                </Badge>
              </td>
              <td className="py-2 px-3">{row.service_name}</td>
              <td className="py-2 px-3">{row.class_name}</td>
              <td className="py-2 px-3">
                <Badge variant={row.xgb_class_name === "CLEAN" ? "ok" : "danger"}>
                  {row.xgb_class_name ?? "?"}
                </Badge>
              </td>
              <td className="py-2 px-3 font-mono">
                {((row.pkts_fwd ?? 0) + (row.pkts_rev ?? 0)).toLocaleString()}
              </td>
              <td className="py-2 px-3 text-muted whitespace-nowrap">
                {timeAgo(row.captured_at)}
              </td>
            </tr>
          ))}
          {items.length === 0 && (
            <tr>
              <td colSpan={7} className="py-8 text-center text-muted">
                No capture verdicts found
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

export default function Verdicts() {
  const [tab, setTab] = useState<Tab>("drops");
  const [offset, setOffset] = useState(0);
  const [d2Type, setD2Type] = useState<string>("");

  const { data, isLoading, error } = useGodVerdicts({
    tab,
    limit: PAGE_SIZE,
    offset,
    d2_type: d2Type || undefined,
  });

  function switchTab(next: Tab) {
    setTab(next);
    setOffset(0);
    setD2Type("");
  }

  if (error) return <ErrorDisplay error={error} />;

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-bold">Verdicts</h1>

      {/* Tabs */}
      <div className="flex items-center gap-2">
        <button
          onClick={() => switchTab("drops")}
          className={`px-4 py-1.5 rounded text-xs font-bold uppercase tracking-wider border transition-colors ${
            tab === "drops"
              ? "bg-accent/20 text-accent border-accent/40"
              : "bg-card text-muted border-border hover:text-text"
          }`}
        >
          DROPs
        </button>
        <button
          onClick={() => switchTab("captures")}
          className={`px-4 py-1.5 rounded text-xs font-bold uppercase tracking-wider border transition-colors ${
            tab === "captures"
              ? "bg-accent/20 text-accent border-accent/40"
              : "bg-card text-muted border-border hover:text-text"
          }`}
        >
          CAPTUREs
        </button>
      </div>

      {/* Captures filter */}
      {tab === "captures" && (
        <div className="flex items-center gap-3">
          <label className="text-xs text-muted">Discrepancy Type</label>
          <select
            value={d2Type}
            onChange={(e) => {
              setD2Type(e.target.value);
              setOffset(0);
            }}
            className="bg-card border border-border rounded px-3 py-1.5 text-xs text-text focus:outline-none focus:border-accent"
          >
            {D2_TYPES.map((t) => (
              <option key={t} value={t === "All" ? "" : t}>
                {t}
              </option>
            ))}
          </select>
        </div>
      )}

      {/* Table */}
      <div className="bg-card border border-border rounded-lg p-4">
        {isLoading && !data ? (
          <PageLoading />
        ) : tab === "drops" ? (
          <DropsTable items={(data?.items ?? []) as GodDropVerdict[]} />
        ) : (
          <CapturesTable items={(data?.items ?? []) as GodCaptureVerdict[]} />
        )}
      </div>

      {/* Pagination */}
      {data && (
        <Pagination
          offset={offset}
          limit={PAGE_SIZE}
          total={data.total}
          onChange={setOffset}
        />
      )}
    </div>
  );
}
