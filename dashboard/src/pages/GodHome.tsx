import { useState, useMemo } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
  ResponsiveContainer,
} from "recharts";

import {
  useGodHealth,
  useGodOverview,
  useGodCatches,
  useGodReputation,
} from "../api/hooks";
import type {
  GodHealth,
  GodReputationRow,
  GodVerdictGroupBreakdown,
} from "../api/types";
import { timeAgo, fmtNumber, cn } from "../lib/format";
import { KpiTile } from "../components/KpiTile";
import { Badge } from "../components/Badge";
import { IpLink } from "../components/IpLink";
import { Pagination } from "../components/Pagination";
import { LoadingSkeleton } from "../components/LoadingSkeleton";

/* ------------------------------------------------------------------ */
/*  Verdict-based colors & labels                                      */
/* ------------------------------------------------------------------ */

function verdictVariant(verdict: string): string {
  if (verdict === "CAPTURE") return "accent";
  if (verdict === "DROP") return "danger";
  return "muted";
}

function verdictGroupColor(group: string): string {
  if (group.startsWith("DIS_")) return "#e3b341";
  if (group.endsWith("_EVD")) return "#f0883e";
  if (group.startsWith("CLN")) return "#56d364";
  if (group.startsWith("RB")) return "#8b949e";
  if (group.endsWith("_NOEVD")) return "#58a6ff";
  return "#8b949e";
}

function verdictGroupVariant(group: string): string {
  if (group.startsWith("DIS_")) return "warn";
  if (group.endsWith("_EVD")) return "warn";
  if (group.startsWith("CLN")) return "ok";
  if (group.startsWith("RB")) return "muted";
  if (group.endsWith("_NOEVD")) return "accent";
  return "muted";
}

/* ------------------------------------------------------------------ */
/*  Pipeline health helpers                                           */
/* ------------------------------------------------------------------ */

type HealthLevel = "ok" | "warn" | "dead";

function scoreHealth(count5: number, lastTs: number): HealthLevel {
  if (count5 > 0) return "ok";
  const ageSec = Math.floor(Date.now() / 1000) - lastTs;
  if (ageSec < 600) return "warn"; // stale < 10 min
  return "dead";
}

function pipelineStatusLevel(s: GodHealth["pipeline_status"]): HealthLevel {
  if (s === "healthy") return "ok";
  if (s === "stale") return "warn";
  return "dead";
}

const DOT_COLORS: Record<HealthLevel, string> = {
  ok: "bg-ok",
  warn: "bg-warn",
  dead: "bg-danger",
};

function HealthDot({ level }: { level: HealthLevel }) {
  return (
    <span
      className={cn(
        "inline-block w-2.5 h-2.5 rounded-full shrink-0",
        DOT_COLORS[level],
        level === "ok" && "animate-pulse",
      )}
    />
  );
}

/* ------------------------------------------------------------------ */
/*  Recharts custom tooltip                                           */
/* ------------------------------------------------------------------ */

function VerdictGroupTooltip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: { payload: GodVerdictGroupBreakdown }[];
}) {
  if (!active || !payload?.[0]) return null;
  const d = payload[0].payload;
  return (
    <div className="bg-panel border border-border rounded px-3 py-2 text-xs shadow-lg">
      <div className="font-bold" style={{ color: verdictGroupColor(d.verdict_group) }}>
        {d.verdict_group}
      </div>
      <div className="text-muted mt-0.5">{fmtNumber(d.count)} IPs</div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Section A: Pipeline Health Bar                                     */
/* ------------------------------------------------------------------ */

function PipelineHealthBar({ health }: { health: GodHealth | undefined }) {
  if (!health) {
    return (
      <div className="bg-panel border border-border rounded-lg px-5 py-3">
        <div className="h-4 w-48 bg-card rounded animate-pulse" />
      </div>
    );
  }

  const s = health.stages;
  const stages: { label: string; sub: string; level: HealthLevel }[] = [
    {
      label: "GOD 1",
      sub: `${fmtNumber(s.god1_scores.count_5min ?? 0)}/5min`,
      level: scoreHealth(s.god1_scores.count_5min ?? 0, s.god1_scores.last_ts),
    },
    {
      label: "Brain",
      sub: `${fmtNumber(s.brain_judgments.count_10min ?? 0)}/10min`,
      level: scoreHealth(s.brain_judgments.count_10min ?? 0, s.brain_judgments.last_ts),
    },
    {
      label: "GOD 2",
      sub: `${fmtNumber(s.god2_verdicts.count_10min ?? 0)}/10min`,
      level: scoreHealth(s.god2_verdicts.count_10min ?? 0, s.god2_verdicts.last_ts),
    },
    {
      label: "Profiles",
      sub: health.pipeline_status,
      level: pipelineStatusLevel(health.pipeline_status),
    },
  ];

  return (
    <div className="bg-panel border border-border rounded-lg px-5 py-3 flex items-center gap-8">
      <span className="text-[10px] text-muted uppercase tracking-wider font-bold">
        Pipeline
      </span>
      {stages.map((s) => (
        <div key={s.label} className="flex items-center gap-2">
          <HealthDot level={s.level} />
          <span className="text-xs font-semibold text-text">{s.label}</span>
          <span className="text-[10px] text-muted tabular-nums">{s.sub}</span>
        </div>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Section B: KPI Tiles                                               */
/* ------------------------------------------------------------------ */

function KpiGrid({
  overview,
  isLoading,
}: {
  overview: ReturnType<typeof useGodOverview>["data"];
  isLoading: boolean;
}) {
  if (isLoading || !overview) return <LoadingSkeleton rows={2} />;

  return (
    <div className="grid grid-cols-6 gap-3">
      <KpiTile
        label="Flows Scored"
        value={fmtNumber(overview.score_log_5min)}
        sub="/5min"
        color="#58a6ff"
      />
      <KpiTile
        label="IPs Tracked"
        value={fmtNumber(overview.total_ips)}
      />
      <KpiTile
        label="Captures"
        value={fmtNumber(overview.capture_count)}
        color="#58a6ff"
      />
      <KpiTile
        label="Evidence IPs"
        value={fmtNumber(overview.evidence_count)}
        color="#f0883e"
      />
      <KpiTile
        label="Drops"
        value={fmtNumber(overview.recent_drops)}
        color="#f85149"
      />
      <KpiTile
        label="Discrepancies"
        value={fmtNumber(overview.discrepancy_count)}
        color="#e3b341"
      />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Section C: Recent Discrepancy Catches                              */
/* ------------------------------------------------------------------ */

function CatchesTable() {
  const { data } = useGodCatches(10);
  const items = data?.items ?? [];

  return (
    <div className="bg-panel border border-border rounded-lg">
      <div className="px-5 py-3 border-b border-border">
        <h2 className="text-sm font-bold text-text">
          Recent Discrepancy Catches
        </h2>
      </div>

      {items.length === 0 ? (
        <div className="px-5 py-8 text-center text-muted text-xs">
          No discrepancy catches yet
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-muted text-[10px] uppercase tracking-wider">
                <th className="px-4 py-2">IP</th>
                <th className="px-4 py-2">Verdict Group</th>
                <th className="px-4 py-2">Evidence</th>
                <th className="px-4 py-2">Services</th>
                <th className="px-4 py-2 text-right">Clean Ratio</th>
                <th className="px-4 py-2 text-right">When</th>
              </tr>
            </thead>
            <tbody>
              {items.map((c) => (
                <tr
                  key={c.src_ip}
                  className="border-t border-border hover:bg-card/50 transition-colors"
                >
                  <td className="px-4 py-2">
                    <IpLink ip={c.src_ip} />
                  </td>
                  <td className="px-4 py-2">
                    <Badge variant={verdictGroupVariant(c.verdict_group ?? "")}>
                      {c.verdict_group}
                    </Badge>
                  </td>
                  <td className="px-4 py-2">
                    <div className="flex flex-wrap gap-1">
                      {Object.entries(
                        (c.evidence ?? []).reduce<Record<string, number>>((acc, e) => {
                          acc[e.event_type] = (acc[e.event_type] || 0) + 1;
                          return acc;
                        }, {})
                      ).map(([etype, cnt]) => (
                        <Badge key={etype} variant="danger">
                          {etype} ({cnt})
                        </Badge>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-2">
                    <div className="flex flex-wrap gap-1">
                      {(c.service_labels ?? []).map((s) => (
                        <Badge
                          key={`${s.service_id}-${s.service_class}`}
                          variant="accent"
                        >
                          {s.service_name}:{s.class_name}
                        </Badge>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-2 text-right tabular-nums font-mono">
                    {((c.xgb_clean_ratio ?? 0) * 100).toFixed(0)}%
                  </td>
                  <td className="px-4 py-2 text-right text-muted">
                    {timeAgo(c.updated_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Section D-Left: Verdict Group Breakdown Chart                      */
/* ------------------------------------------------------------------ */

function VerdictGroupChart({
  breakdown,
}: {
  breakdown: GodVerdictGroupBreakdown[];
}) {
  const sorted = useMemo(
    () => [...breakdown].sort((a, b) => b.count - a.count),
    [breakdown],
  );

  if (sorted.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-muted text-xs">
        No data
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={sorted.length * 40 + 20}>
      <BarChart data={sorted} layout="vertical" margin={{ left: 10, right: 20 }}>
        <XAxis type="number" hide />
        <YAxis
          type="category"
          dataKey="verdict_group"
          width={130}
          tick={{ fill: "#e6edf3", fontSize: 11 }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip
          content={<VerdictGroupTooltip />}
          cursor={{ fill: "rgba(255,255,255,0.04)" }}
        />
        <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={22}>
          {sorted.map((entry) => (
            <Cell
              key={entry.verdict_group}
              fill={verdictGroupColor(entry.verdict_group)}
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

/* ------------------------------------------------------------------ */
/*  Section D-Right: Per-Service Summary Table                         */
/* ------------------------------------------------------------------ */

function ServiceSummaryTable({
  services,
}: {
  services: ReturnType<typeof useGodOverview>["data"] extends infer T
    ? T extends { service_summary: infer S }
      ? S
      : never
    : never;
}) {
  if (!services || services.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-muted text-xs">
        No services
      </div>
    );
  }

  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="text-left text-muted text-[10px] uppercase tracking-wider">
          <th className="px-4 py-2">Service</th>
          <th className="px-4 py-2 text-right">IPs</th>
          <th className="px-4 py-2 text-right">Evidence IPs</th>
          <th className="px-4 py-2 text-right">Events</th>
        </tr>
      </thead>
      <tbody>
        {services.map((s) => (
          <tr
            key={s.service_id}
            className="border-t border-border hover:bg-card/50 transition-colors"
          >
            <td className="px-4 py-2 font-semibold text-text">{s.service_name}</td>
            <td className="px-4 py-2 text-right tabular-nums text-accent">
              {fmtNumber(s.ip_count)}
            </td>
            <td className="px-4 py-2 text-right tabular-nums text-warn">
              {fmtNumber(s.with_evidence)}
            </td>
            <td className="px-4 py-2 text-right tabular-nums text-danger">
              {fmtNumber(s.total_events)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/* ------------------------------------------------------------------ */
/*  Section E: IP Reputation Table                                     */
/* ------------------------------------------------------------------ */

const VERDICT_OPTIONS = [
  { value: "", label: "All Verdicts" },
  { value: "CAPTURE", label: "Capture" },
  { value: "DROP", label: "Drop" },
];

const SORT_COLUMNS: {
  key: string;
  label: string;
  field: keyof GodReputationRow;
}[] = [
  { key: "total_flows", label: "Flows", field: "total_flows" },
  { key: "xgb_clean_ratio", label: "Clean Ratio", field: "xgb_clean_ratio" },
  { key: "evidence_count", label: "Evidence", field: "evidence_count" },
  { key: "unique_ports", label: "Ports", field: "unique_ports" },
  { key: "unique_dsts", label: "Dsts", field: "unique_dsts" },
  { key: "updated_at", label: "Last Seen", field: "updated_at" },
];

function ReputationTable() {
  const [verdict, setVerdict] = useState("");
  const [verdictGroup, setVerdictGroup] = useState("");
  const [evidenceOnly, setEvidenceOnly] = useState(false);
  const [offset, setOffset] = useState(0);
  const [sortKey, setSortKey] = useState("total_flows");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const LIMIT = 50;

  const params = useMemo(
    () => ({
      verdict: verdict || undefined,
      verdict_group: verdictGroup || undefined,
      has_evidence: evidenceOnly ? 1 : undefined,
      limit: LIMIT,
      offset,
      sort: sortKey,
      order: sortOrder,
    }),
    [verdict, verdictGroup, evidenceOnly, offset, sortKey, sortOrder],
  );

  const { data, isLoading } = useGodReputation(params);
  const items = data?.items ?? [];
  const total = data?.total ?? 0;

  function handleSort(key: string) {
    if (sortKey === key) {
      setSortOrder((o) => (o === "desc" ? "asc" : "desc"));
    } else {
      setSortKey(key);
      setSortOrder("desc");
    }
    setOffset(0);
  }

  function resetFilters() {
    setVerdict("");
    setVerdictGroup("");
    setEvidenceOnly(false);
    setOffset(0);
  }

  return (
    <div className="bg-panel border border-border rounded-lg">
      {/* header + filters */}
      <div className="px-5 py-3 border-b border-border flex items-center gap-4 flex-wrap">
        <h2 className="text-sm font-bold text-text mr-auto">IP Reputation</h2>

        <select
          value={verdict}
          onChange={(e) => {
            setVerdict(e.target.value);
            setOffset(0);
          }}
          className="bg-card border border-border rounded px-2 py-1 text-xs text-text"
        >
          {VERDICT_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>

        <input
          type="text"
          value={verdictGroup}
          onChange={(e) => {
            setVerdictGroup(e.target.value);
            setOffset(0);
          }}
          placeholder="Verdict group prefix..."
          className="bg-card border border-border rounded px-2 py-1 text-xs text-text w-44"
        />

        <label className="flex items-center gap-1.5 text-xs text-muted cursor-pointer select-none">
          <input
            type="checkbox"
            checked={evidenceOnly}
            onChange={(e) => {
              setEvidenceOnly(e.target.checked);
              setOffset(0);
            }}
            className="accent-accent"
          />
          Evidence only
        </label>

        {(verdict || verdictGroup || evidenceOnly) && (
          <button
            onClick={resetFilters}
            className="text-[10px] text-muted hover:text-text underline"
          >
            Reset
          </button>
        )}
      </div>

      {/* table */}
      {isLoading && items.length === 0 ? (
        <LoadingSkeleton rows={6} />
      ) : items.length === 0 ? (
        <div className="px-5 py-8 text-center text-muted text-xs">
          No IPs match current filters
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-muted text-[10px] uppercase tracking-wider">
                <th className="px-4 py-2">IP</th>
                <th className="px-4 py-2">Verdict</th>
                <th className="px-4 py-2">Verdict Group</th>
                <th className="px-4 py-2 text-center">Evidence</th>
                <th className="px-4 py-2">XGB Class</th>
                {SORT_COLUMNS.map((col) => (
                  <th
                    key={col.key}
                    className="px-4 py-2 text-right cursor-pointer hover:text-text select-none"
                    onClick={() => handleSort(col.key)}
                  >
                    {col.label}
                    {sortKey === col.key && (
                      <span className="ml-0.5">
                        {sortOrder === "desc" ? " \u25BC" : " \u25B2"}
                      </span>
                    )}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.map((row) => (
                <tr
                  key={row.src_ip}
                  className="border-t border-border hover:bg-card/50 transition-colors"
                >
                  <td className="px-4 py-2">
                    <IpLink ip={row.src_ip} />
                  </td>
                  <td className="px-4 py-2">
                    <Badge variant={verdictVariant(row.verdict ?? "")}>
                      {row.verdict}
                    </Badge>
                  </td>
                  <td className="px-4 py-2">
                    <Badge variant={verdictGroupVariant(row.verdict_group ?? "")}>
                      {row.verdict_group}
                    </Badge>
                  </td>
                  <td className="px-4 py-2 text-center">
                    {(row.evidence_count ?? 0) > 0 ? (
                      <span className="text-ok font-bold">{row.evidence_count}</span>
                    ) : (
                      <span className="text-muted">{"\u2014"}</span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-text">
                    {row.xgb_class_name}
                  </td>
                  {/* Flows */}
                  <td className="px-4 py-2 text-right tabular-nums">
                    {fmtNumber(row.total_flows)}
                  </td>
                  {/* Clean Ratio */}
                  <td className="px-4 py-2 text-right tabular-nums font-mono">
                    {((row.xgb_clean_ratio ?? 0) * 100).toFixed(0)}%
                  </td>
                  {/* Evidence Count */}
                  <td className="px-4 py-2 text-right tabular-nums">
                    {row.evidence_count ?? 0}
                  </td>
                  {/* Ports */}
                  <td className="px-4 py-2 text-right tabular-nums">
                    {fmtNumber(row.unique_ports)}
                  </td>
                  {/* Dsts */}
                  <td className="px-4 py-2 text-right tabular-nums">
                    {fmtNumber(row.unique_dsts)}
                  </td>
                  {/* Last Seen */}
                  <td className="px-4 py-2 text-right text-muted whitespace-nowrap">
                    {timeAgo(row.updated_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* pagination */}
      <div className="px-4 border-t border-border">
        <Pagination
          offset={offset}
          limit={LIMIT}
          total={total}
          onChange={setOffset}
        />
      </div>
    </div>
  );
}

/* ================================================================== */
/*  Page root                                                         */
/* ================================================================== */

export default function GodHome() {
  const { data: health } = useGodHealth();
  const { data: overview, isLoading: overviewLoading } = useGodOverview();

  return (
    <div className="space-y-4">
      {/* Section A: Pipeline Health */}
      <PipelineHealthBar health={health} />

      {/* Section B: KPI Tiles */}
      <KpiGrid overview={overview} isLoading={overviewLoading} />

      {/* Section C: Recent Catches */}
      <CatchesTable />

      {/* Section D: Verdict Group + Service panels side-by-side */}
      <div className="grid grid-cols-2 gap-4">
        {/* Left: Verdict Group Breakdown */}
        <div className="bg-panel border border-border rounded-lg">
          <div className="px-5 py-3 border-b border-border">
            <h2 className="text-sm font-bold text-text">
              Verdict Group Breakdown
            </h2>
          </div>
          <div className="p-4">
            {overview ? (
              <VerdictGroupChart breakdown={overview.verdict_group_breakdown ?? []} />
            ) : (
              <LoadingSkeleton rows={4} />
            )}
          </div>
        </div>

        {/* Right: Per-Service Summary */}
        <div className="bg-panel border border-border rounded-lg">
          <div className="px-5 py-3 border-b border-border">
            <h2 className="text-sm font-bold text-text">
              Per-Service Summary
            </h2>
          </div>
          <div className="p-2">
            {overview ? (
              <ServiceSummaryTable services={overview.service_summary ?? []} />
            ) : (
              <LoadingSkeleton rows={5} />
            )}
          </div>
        </div>
      </div>

      {/* Section E: IP Reputation Table */}
      <ReputationTable />
    </div>
  );
}
