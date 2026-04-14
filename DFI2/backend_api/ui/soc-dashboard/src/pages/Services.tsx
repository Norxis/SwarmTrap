import { useGodServices } from "../api/hooks";
import type {
  GodServiceDetail,
  GodServiceClassDist,
  GodBudgetEntry,
} from "../api/types";
import { PageLoading } from "../components/LoadingSkeleton";
import { fmtNumber } from "../lib/format";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

// ── Color scale per class_id ──

const CLASS_COLORS: Record<number, string> = {
  0: "#8b949e", // gray
  1: "#58a6ff", // blue
  2: "#e3b341", // yellow
  3: "#f0883e", // orange
  4: "#f85149", // red
  5: "#da3633", // dark red
};

function classColor(classId: number): string {
  return CLASS_COLORS[classId] ?? "#8b949e";
}

// ── Service Card ──

function ServiceCard({ service }: { service: GodServiceDetail }) {
  return (
    <div className="bg-card border border-border rounded-lg p-4 space-y-4">
      {/* Header */}
      <h2 className="text-sm font-bold">{service.service_name}</h2>

      {/* Class Distribution Chart */}
      <ClassDistChart classes={service.classes} />

      {/* Budget Status */}
      <BudgetTable budget={service.budgets} />

      {/* Top IPs — not available in current backend */}
    </div>
  );
}

// ── Class Distribution horizontal bar chart ──

function ClassDistChart({ classes }: { classes: GodServiceClassDist[] }) {
  if (!classes.length) {
    return (
      <div className="text-[10px] text-muted">No class distribution data</div>
    );
  }

  const data = classes
    .slice()
    .sort((a, b) => a.class_id - b.class_id)
    .map((c) => ({
      name: c.class_name,
      count: c.count,
      classId: c.class_id,
    }));

  return (
    <div>
      <h3 className="text-[10px] text-muted uppercase tracking-wider mb-2">
        Class Distribution
      </h3>
      <ResponsiveContainer width="100%" height={data.length * 32 + 16}>
        <BarChart data={data} layout="vertical" margin={{ left: 4, right: 12, top: 4, bottom: 4 }}>
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey="name"
            width={80}
            tick={{ fontSize: 10, fill: "#8b949e" }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip
            contentStyle={{
              background: "#161b22",
              border: "1px solid #30363d",
              borderRadius: 6,
              fontSize: 11,
            }}
            labelStyle={{ color: "#e6edf3" }}
            itemStyle={{ color: "#e6edf3" }}
            formatter={(value: number | undefined) => [fmtNumber(value ?? 0), "IPs"]}
          />
          <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={18}>
            {data.map((entry) => (
              <Cell key={entry.classId} fill={classColor(entry.classId)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── Budget mini table ──

function BudgetTable({ budget }: { budget: GodBudgetEntry[] }) {
  if (!budget.length) {
    return (
      <div>
        <h3 className="text-[10px] text-muted uppercase tracking-wider mb-2">
          Budget Status
        </h3>
        <span className="text-[10px] text-muted">No budget data</span>
      </div>
    );
  }

  return (
    <div>
      <h3 className="text-[10px] text-muted uppercase tracking-wider mb-2">
        Budget Status
      </h3>
      <table className="w-full text-[11px]">
        <thead>
          <tr className="text-muted text-left border-b border-border/50">
            <th className="pb-1 font-medium">Class</th>
            <th className="pb-1 font-medium text-right">Captured</th>
            <th className="pb-1 font-medium text-right">Target</th>
            <th className="pb-1 font-medium text-right">Deficit</th>
          </tr>
        </thead>
        <tbody>
          {budget.map((b) => {
            const deficit = b.group_target - b.group_count;
            const critical = b.group_target > 0 && deficit > b.group_target / 2;
            return (
              <tr key={b.class_id} className="border-b border-border/20">
                <td className="py-1">{b.class_name}</td>
                <td className="py-1 text-right tabular-nums">
                  {fmtNumber(b.group_count)}
                </td>
                <td className="py-1 text-right tabular-nums text-muted">
                  {fmtNumber(b.group_target)}
                </td>
                <td
                  className={`py-1 text-right tabular-nums ${
                    critical ? "text-danger font-bold" : "text-muted"
                  }`}
                >
                  {deficit > 0 ? `-${fmtNumber(deficit)}` : fmtNumber(deficit)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── Top IPs ──

// ── Main Page ──

export default function Services() {
  const { data, isLoading } = useGodServices();

  if (isLoading || !data) return <PageLoading />;

  const services = data.services;

  if (!services || services.length === 0) {
    return (
      <div className="space-y-4">
        <h1 className="text-lg font-bold">Per-Service Breakdown</h1>
        <div className="text-xs text-muted text-center py-8">
          No services data available
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-bold">Per-Service Breakdown</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {services.map((svc, idx) => (
          <div
            key={svc.service_id}
            className={
              services.length % 2 !== 0 && idx === services.length - 1
                ? "md:col-span-1"
                : ""
            }
          >
            <ServiceCard service={svc} />
          </div>
        ))}
      </div>
    </div>
  );
}
