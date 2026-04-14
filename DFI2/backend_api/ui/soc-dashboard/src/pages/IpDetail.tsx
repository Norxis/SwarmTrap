import { useMemo } from "react";
import { useParams } from "react-router-dom";
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

import { useGodIpDetail } from "../api/hooks";
import type {
  GodIpDetail,
  GodTimelinePoint,
  GodEvidenceEvent,
  GodServiceLabel,
} from "../api/types";
import { Badge, LoadingSkeleton } from "../components";
import { timeAgo, fmtTs, fmtNumber, cn } from "../lib/format";

/* ---- XGB class colors ---- */

const XGB_COLORS: Record<number, string> = {
  0: "#58a6ff", // RECON
  1: "#e3b341", // KNOCK
  2: "#f0883e", // BRUTE
  3: "#f85149", // EXPLOIT
  4: "#56d364", // CLEAN
};

const XGB_CLASS_NAMES: Record<number, string> = {
  0: "RECON",
  1: "KNOCK",
  2: "BRUTE",
  3: "EXPLOIT",
  4: "CLEAN",
};

function xgbColor(cls: number): string {
  return XGB_COLORS[cls] ?? "#8b949e";
}

/* ---- verdict badge ---- */

function verdictVariant(verdict: string): string {
  if (verdict === "CAPTURE") return "accent";
  if (verdict === "DROP") return "danger";
  return "muted";
}

function verdictGroupVariant(group: string): string {
  if (group.startsWith("DIS_")) return "warn";
  if (group.endsWith("_EVD")) return "warn";
  if (group.startsWith("CLN")) return "ok";
  if (group.startsWith("RB")) return "muted";
  if (group.endsWith("_NOEVD")) return "accent";
  return "muted";
}

/* ---- evidence type badge ---- */

function evidenceTypeBadge(eventType: string): string {
  const t = eventType.toLowerCase();
  if (t.includes("command") || t.includes("escalation") || t.includes("exploit"))
    return "danger";
  if (t.includes("auth") || t.includes("credential") || t.includes("brute"))
    return "warn";
  return "muted";
}

/* ---- service class badge ---- */

function serviceClassVariant(classId: number): string {
  if (classId >= 3) return "danger";
  if (classId >= 1) return "warn";
  return "muted";
}

/* ---- custom scatter tooltip ---- */

function TimelineTooltipContent({
  active,
  payload,
}: {
  active?: boolean;
  payload?: Array<{ payload: GodTimelinePoint }>;
}) {
  if (!active || !payload || payload.length === 0) return null;
  const p = payload[0].payload;
  return (
    <div className="bg-panel border border-border rounded-lg px-3 py-2 text-xs space-y-1 shadow-lg">
      <div className="font-bold" style={{ color: xgbColor(p.xgb_class) }}>
        {p.xgb_class_name || XGB_CLASS_NAMES[p.xgb_class] || `Class ${p.xgb_class}`}
      </div>
      <div>
        <span className="text-muted">Confidence: </span>
        <span className="tabular-nums">{(p.xgb_confidence * 100).toFixed(1)}%</span>
      </div>
      <div>
        <span className="text-muted">Port: </span>
        <span className="tabular-nums">{p.dst_port}</span>
      </div>
      <div>
        <span className="text-muted">Pkts Rev: </span>
        <span className="tabular-nums">{p.pkts_rev}</span>
      </div>
      <div>
        <span className="text-muted">VLAN: </span>
        <span className="tabular-nums">
          {p.vlan_id}
          {p.vlan_id === 100 ? " (ingress)" : p.vlan_id === 101 ? " (egress)" : ""}
        </span>
      </div>
      <div className="text-muted">{fmtTs(p.ts)}</div>
    </div>
  );
}

/* ---- field grid helper ---- */

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[10px] text-muted uppercase tracking-wider">{label}</span>
      <span className="text-sm tabular-nums">{value}</span>
    </div>
  );
}

/* ---- Panel 1: Profile Summary ---- */

function ProfilePanel({
  rep,
}: {
  rep: GodIpDetail["profile"];
}) {
  if (!rep) {
    return (
      <div className="bg-panel border border-border rounded-lg p-6">
        <div className="text-muted text-sm">IP not found in profile database</div>
      </div>
    );
  }

  return (
    <div className="bg-panel border border-border rounded-lg p-5 space-y-4">
      {/* header row */}
      <div className="flex items-center flex-wrap gap-3">
        <span className="text-xl font-bold font-mono text-accent">{rep.src_ip}</span>
        <Badge variant={verdictVariant(rep.verdict ?? "")}>
          {rep.verdict}
        </Badge>
        <Badge variant={verdictGroupVariant(rep.verdict_group ?? "")}>
          {rep.verdict_group}
        </Badge>
        {(rep.evidence_count ?? 0) > 0 && (
          <Badge variant="danger">EVIDENCE ({rep.evidence_count})</Badge>
        )}
      </div>

      {/* field grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Field
          label="XGB Class"
          value={
            <span style={{ color: xgbColor(rep.best_xgb_class) }}>
              {rep.xgb_class_name || XGB_CLASS_NAMES[rep.best_xgb_class] || `Class ${rep.best_xgb_class}`}
            </span>
          }
        />
        <Field
          label="Clean Ratio"
          value={`${((rep.xgb_clean_ratio ?? 0) * 100).toFixed(1)}%`}
        />
        <Field label="Total Flows" value={fmtNumber(rep.total_flows)} />
        <Field label="Unique Ports" value={fmtNumber(rep.unique_ports)} />
        <Field label="Unique Dsts" value={fmtNumber(rep.unique_dsts)} />
        <Field label="Evidence Count" value={String(rep.evidence_count ?? 0)} />
        <Field label="First Seen" value={rep.first_seen ? fmtTs(rep.first_seen) : "--"} />
        <Field label="Last Seen" value={rep.last_seen ? fmtTs(rep.last_seen) : "--"} />
      </div>

      {/* secondary info */}
      <div className="flex items-center gap-4 text-xs text-muted">
        <span>Evidence Types: {rep.evidence_types ? `0x${rep.evidence_types.toString(16)}` : "none"}</span>
        <span>Updated: {timeAgo(rep.updated_at)}</span>
      </div>
    </div>
  );
}

/* ---- Panel 2: XGB Score Timeline ---- */

function TimelinePanel({ timeline }: { timeline: GodTimelinePoint[] }) {
  const sorted = useMemo(
    () => [...timeline].sort((a, b) => a.ts - b.ts),
    [timeline],
  );

  if (sorted.length === 0) {
    return (
      <div className="bg-panel border border-border rounded-lg p-5">
        <h2 className="text-xs text-muted uppercase tracking-wider font-bold mb-3">
          XGB Score Timeline
        </h2>
        <div className="text-muted text-xs">No timeline data available</div>
      </div>
    );
  }

  return (
    <div className="bg-panel border border-border rounded-lg p-5">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-xs text-muted uppercase tracking-wider font-bold">
          XGB Score Timeline
        </h2>
        <span className="text-[10px] text-muted">{sorted.length} points</span>
      </div>

      {/* legend */}
      <div className="flex items-center gap-4 mb-3 text-[10px]">
        {Object.entries(XGB_CLASS_NAMES).map(([cls, name]) => (
          <div key={cls} className="flex items-center gap-1.5">
            <span
              className="inline-block w-2.5 h-2.5 rounded-full"
              style={{ background: XGB_COLORS[Number(cls)] }}
            />
            <span>{name}</span>
          </div>
        ))}
      </div>

      <ResponsiveContainer width="100%" height={280}>
        <ScatterChart margin={{ top: 8, right: 12, bottom: 8, left: 0 }}>
          <CartesianGrid
            strokeDasharray="3 3"
            stroke="#30363d"
            strokeOpacity={0.5}
          />
          <XAxis
            dataKey="ts"
            type="number"
            domain={["dataMin", "dataMax"]}
            tickFormatter={(v: number) => {
              const d = new Date(v * 1000);
              return `${d.getMonth() + 1}/${d.getDate()} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
            }}
            tick={{ fill: "#8b949e", fontSize: 10 }}
            stroke="#30363d"
          />
          <YAxis
            dataKey="xgb_confidence"
            type="number"
            domain={[0, 1]}
            tickFormatter={(v: number) => `${(v * 100).toFixed(0)}%`}
            tick={{ fill: "#8b949e", fontSize: 10 }}
            stroke="#30363d"
            width={45}
          />
          <RechartsTooltip
            content={<TimelineTooltipContent />}
            cursor={{ strokeDasharray: "3 3", stroke: "#8b949e" }}
          />
          <Scatter data={sorted} shape="circle">
            {sorted.map((entry, idx) => (
              <Cell
                key={idx}
                fill={xgbColor(entry.xgb_class)}
                fillOpacity={0.8}
                stroke={xgbColor(entry.xgb_class)}
                strokeWidth={1}
              />
            ))}
          </Scatter>
        </ScatterChart>
      </ResponsiveContainer>
    </div>
  );
}

/* ---- Panel 3: Evidence Events ---- */

function EvidencePanel({ evidence }: { evidence: GodEvidenceEvent[] }) {
  const sorted = useMemo(
    () => [...evidence].sort((a, b) => b.ts - a.ts),
    [evidence],
  );

  return (
    <div className="bg-panel border border-border rounded-lg p-5">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-xs text-muted uppercase tracking-wider font-bold">
          Evidence Events
        </h2>
        <span className="text-[10px] text-muted">{evidence.length} events</span>
      </div>

      {sorted.length === 0 ? (
        <div className="text-muted text-xs">No evidence events</div>
      ) : (
        <div className="overflow-auto max-h-80">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-muted uppercase tracking-wider text-[10px] border-b border-border">
                <th className="pb-2 pr-3">Time</th>
                <th className="pb-2 pr-3">Type</th>
                <th className="pb-2 pr-3">Source</th>
                <th className="pb-2">Detail</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((ev, i) => (
                <tr
                  key={i}
                  className={cn(
                    "border-b border-border/50",
                    i % 2 === 0 ? "bg-card/20" : "",
                  )}
                >
                  <td className="py-1.5 pr-3 text-muted whitespace-nowrap tabular-nums">
                    {fmtTs(ev.ts)}
                  </td>
                  <td className="py-1.5 pr-3">
                    <Badge variant={evidenceTypeBadge(ev.event_type)}>
                      {ev.event_type}
                    </Badge>
                  </td>
                  <td className="py-1.5 pr-3 text-muted whitespace-nowrap">
                    {ev.source_program}
                  </td>
                  <td className="py-1.5 max-w-md truncate" title={ev.event_detail}>
                    {ev.event_detail}
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

/* ---- Panel 4: Service Labels ---- */

function ServicesPanel({ services }: { services: GodServiceLabel[] }) {
  return (
    <div className="bg-panel border border-border rounded-lg p-5">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-xs text-muted uppercase tracking-wider font-bold">
          Service Labels
        </h2>
        <span className="text-[10px] text-muted">{services.length} services</span>
      </div>

      {services.length === 0 ? (
        <div className="text-muted text-xs">No service labels</div>
      ) : (
        <div className="overflow-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-muted uppercase tracking-wider text-[10px] border-b border-border">
                <th className="pb-2 pr-3">Service</th>
                <th className="pb-2">Behavioral Class</th>
              </tr>
            </thead>
            <tbody>
              {services.map((svc, i) => (
                <tr
                  key={i}
                  className={cn(
                    "border-b border-border/50",
                    i % 2 === 0 ? "bg-card/20" : "",
                  )}
                >
                  <td className="py-1.5 pr-3 font-mono">{svc.service_name}</td>
                  <td className="py-1.5">
                    <Badge variant={serviceClassVariant(svc.service_class)}>
                      {svc.class_name}
                    </Badge>
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

/* ---- Main Page ---- */

export default function IpDetail() {
  const params = useParams();
  const ip = params["*"] ?? "";

  const { data, isLoading } = useGodIpDetail(ip);

  if (!ip) {
    return (
      <div className="p-4 text-muted text-sm">
        No IP address specified.
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="p-4 space-y-4">
        <LoadingSkeleton rows={3} />
        <LoadingSkeleton rows={6} />
        <LoadingSkeleton rows={4} />
      </div>
    );
  }

  if (!data) {
    return (
      <div className="p-4">
        <div className="bg-panel border border-border rounded-lg p-6">
          <div className="text-muted text-sm">IP not found in reputation database</div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 space-y-4">
      {/* Panel 1: Profile Summary */}
      <ProfilePanel rep={data.profile} />

      {/* Panel 2: XGB Score Timeline */}
      <TimelinePanel timeline={data.timeline} />

      {/* Panel 3: Evidence Events */}
      <EvidencePanel evidence={data.evidence} />

      {/* Panel 4: Service Labels */}
      <ServicesPanel services={data.service_labels} />
    </div>
  );
}
