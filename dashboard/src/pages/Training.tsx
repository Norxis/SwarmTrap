import { useState } from "react";
import { useGodTraining } from "../api/hooks";
import type {
  GodD2Category,
  GodReadinessCategory,
  GodXgbClass,
  GodModelEntry,
  GodBudgetRow,
} from "../api/types";
import { Badge } from "../components";
import { PageLoading } from "../components/LoadingSkeleton";
import { fmtNumber, cn } from "../lib/format";

function labelVariant(label: string): string {
  if (label === "ATTACK") return "danger";
  if (label === "CLEAN") return "ok";
  if (label === "EXCLUDED") return "warn";
  return "muted";
}

export default function Training() {
  const training = useGodTraining();
  const [budgetsOpen, setBudgetsOpen] = useState(false);
  const [catsOpen, setCatsOpen] = useState(false);
  const [attackOpen, setAttackOpen] = useState(false);

  if (training.isLoading) return <PageLoading />;

  const d = training.data;
  const cats = d?.by_category?.categories ?? [];
  const totals = d?.by_category?.totals ?? { attack: 0, clean: 0, excluded: 0 };
  const readiness = d?.fiveclass_readiness;
  const models = d?.models ?? [];
  const budgets = d?.service_budgets ?? [];

  return (
    <div className="space-y-6">
      <h1 className="text-lg font-bold">Training</h1>

      {/* ---- D2 Capture Summary ---- */}
      <div className="space-y-3">
        <h2 className="text-sm font-bold text-muted uppercase tracking-wider">
          D2 Capture Data
        </h2>
        <div className="flex gap-3 flex-wrap">
          <div className="bg-card border border-border rounded-lg px-4 py-3 text-center min-w-[120px]">
            <div className="text-2xl font-bold tabular-nums">{fmtNumber(d?.total_captured ?? 0)}</div>
            <div className="text-[10px] text-muted">Total Captured</div>
          </div>
          <div className="bg-card border border-border rounded-lg px-4 py-3 text-center min-w-[120px]">
            <div className="text-2xl font-bold tabular-nums text-danger">{fmtNumber(totals.attack)}</div>
            <div className="text-[10px] text-muted">Attack</div>
          </div>
          <div className="bg-card border border-border rounded-lg px-4 py-3 text-center min-w-[120px]">
            <div className="text-2xl font-bold tabular-nums text-ok">{fmtNumber(totals.clean)}</div>
            <div className="text-[10px] text-muted">Clean</div>
          </div>
          <div className="bg-card border border-border rounded-lg px-4 py-3 text-center min-w-[120px]">
            <div className="text-2xl font-bold tabular-nums text-warn">{fmtNumber(totals.excluded)}</div>
            <div className="text-[10px] text-muted">Excluded (FP)</div>
          </div>
        </div>

        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <button
            onClick={() => setCatsOpen(!catsOpen)}
            className="w-full flex items-center justify-between px-4 py-2.5 text-xs hover:bg-panel/50"
          >
            <span className="font-medium">Categories <span className="text-muted">({cats.length})</span></span>
            <span className="text-muted text-[10px]">{catsOpen ? "Collapse" : "Expand"}</span>
          </button>
          {catsOpen && (
            <div className="border-t border-border">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border bg-panel">
                    <th className="text-left px-4 py-2 text-muted font-medium">Category</th>
                    <th className="text-left px-4 py-2 text-muted font-medium">Label</th>
                    <th className="text-right px-4 py-2 text-muted font-medium">Rows</th>
                    <th className="text-right px-4 py-2 text-muted font-medium">Types</th>
                    <th className="text-left px-4 py-2 text-muted font-medium">Training</th>
                  </tr>
                </thead>
                <tbody>
                  {cats.map((c: GodD2Category) => (
                    <tr key={c.key} className="border-b border-border/50 hover:bg-panel/50">
                      <td className="px-4 py-2 font-mono font-medium">{c.key}</td>
                      <td className="px-4 py-2 text-muted">{c.label}</td>
                      <td className="px-4 py-2 text-right tabular-nums">{fmtNumber(c.count)}</td>
                      <td className="px-4 py-2 text-right tabular-nums text-muted">{c.types}</td>
                      <td className="px-4 py-2">
                        <Badge variant={labelVariant(c.training_label)}>{c.training_label}</Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* ---- Attack Readiness ---- */}
      {readiness && (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <button
            onClick={() => setAttackOpen(!attackOpen)}
            className="w-full flex items-center justify-between px-4 py-2.5 text-xs hover:bg-panel/50"
          >
            <span className="font-medium">
              Attack Data Available <span className="text-danger font-bold">{fmtNumber(readiness.total_attack)}</span>
              <span className="text-muted ml-2">({(readiness.categories ?? []).length} groups)</span>
            </span>
            <span className="text-muted text-[10px]">{attackOpen ? "Collapse" : "Expand"}</span>
          </button>
          {attackOpen && (
            <div className="border-t border-border px-4 py-3">
              <div className="text-[10px] text-muted mb-3">Source: {readiness.source}</div>
              <div className="space-y-2">
                {(readiness.categories ?? []).map((c: GodReadinessCategory) => (
                  <div key={c.key} className="flex items-center gap-3 text-xs">
                    <span className="font-mono w-[100px] shrink-0">{c.key}</span>
                    <span className="text-muted w-[140px] shrink-0">{c.label}</span>
                    <span className="tabular-nums w-[80px] text-right shrink-0">{fmtNumber(c.count)}</span>
                    <span className="tabular-nums text-muted text-[10px] w-[70px] text-right shrink-0">{fmtNumber(c.ips)} IPs</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ---- 5-Class Distribution ---- */}
      {(d?.fiveclass_by_xgb ?? []).length > 0 && (
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-muted uppercase tracking-wider">
            5-Class Distribution (Training Data)
          </h2>
          <div className="grid grid-cols-5 gap-3">
            {(d?.fiveclass_by_xgb ?? []).map((c: GodXgbClass) => {
              const isAttack = c.class_id < 4;
              return (
                <div key={c.class_id} className={cn(
                  "bg-card border rounded-lg px-4 py-3 text-center",
                  isAttack ? "border-danger/30" : "border-ok/30"
                )}>
                  <div className={cn("text-[10px] font-bold uppercase tracking-wider mb-1", isAttack ? "text-danger" : "text-ok")}>
                    {c.name}
                  </div>
                  <div className="text-xl font-bold tabular-nums">{fmtNumber(c.count)}</div>
                  <div className="text-[10px] text-muted">{fmtNumber(c.ips)} IPs</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ---- Models ---- */}
      <div className="space-y-3">
        <h2 className="text-sm font-bold text-muted uppercase tracking-wider">
          Models ({models.length})
        </h2>
        <div className="bg-card border border-border rounded-lg overflow-hidden overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-panel">
                <th className="text-left px-4 py-2 text-muted font-medium">Model</th>
                <th className="text-left px-4 py-2 text-muted font-medium">Classes</th>
                <th className="text-right px-4 py-2 text-muted font-medium">Accuracy</th>
                <th className="text-right px-4 py-2 text-muted font-medium">F1</th>
                <th className="text-right px-4 py-2 text-muted font-medium">Samples</th>
                <th className="text-right px-4 py-2 text-muted font-medium">Size</th>
                <th className="text-center px-4 py-2 text-muted font-medium">Deploy</th>
              </tr>
            </thead>
            <tbody>
              {models.map((m: GodModelEntry) => (
                <tr key={m.file} className={cn(
                  "border-b border-border/50 hover:bg-panel/50",
                  m.deployed_on.length > 0 && "bg-ok/5"
                )}>
                  <td className="px-4 py-2">
                    <div className="font-mono font-medium">{m.model_name}</div>
                    <div className="text-[10px] text-muted">{m.timestamp}</div>
                  </td>
                  <td className="px-4 py-2 text-muted">{m.classes.join(", ") || "binary"}</td>
                  <td className="px-4 py-2 text-right tabular-nums">
                    <span className={cn(m.accuracy >= 0.95 ? "text-ok" : m.accuracy >= 0.9 ? "text-accent" : "text-warn")}>
                      {(m.accuracy * 100).toFixed(2)}%
                    </span>
                  </td>
                  <td className="px-4 py-2 text-right tabular-nums">
                    <span className={cn(m.macro_f1 >= 0.95 ? "text-ok" : m.macro_f1 >= 0.9 ? "text-accent" : "text-warn")}>
                      {(m.macro_f1 * 100).toFixed(2)}%
                    </span>
                  </td>
                  <td className="px-4 py-2 text-right tabular-nums text-muted">{fmtNumber(m.n_samples)}</td>
                  <td className="px-4 py-2 text-right tabular-nums text-muted">{m.size_mb}MB</td>
                  <td className="px-4 py-2 text-center">
                    {m.deployed_on.length > 0 ? (
                      <Badge variant="ok">{m.deployed_on.join(", ")}</Badge>
                    ) : (
                      <span className="text-muted">--</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ---- Service Budgets (collapsible) ---- */}
      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <button
          onClick={() => setBudgetsOpen(!budgetsOpen)}
          className="w-full flex items-center justify-between px-4 py-2.5 text-xs hover:bg-panel/50"
        >
          <span className="font-medium">Service Budgets <span className="text-muted">({budgets.length})</span></span>
          <span className="text-muted text-[10px]">{budgetsOpen ? "Collapse" : "Expand"}</span>
        </button>
        {budgetsOpen && (
          <div className="border-t border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-panel">
                  <th className="text-left px-4 py-2 text-muted font-medium">Service</th>
                  <th className="text-left px-4 py-2 text-muted font-medium">Class</th>
                  <th className="text-right px-4 py-2 text-muted font-medium">Captured</th>
                  <th className="text-right px-4 py-2 text-muted font-medium">Target</th>
                  <th className="text-right px-4 py-2 text-muted font-medium">Deficit</th>
                </tr>
              </thead>
              <tbody>
                {budgets.map((b: GodBudgetRow, i: number) => (
                  <tr key={`${b.service_id}-${b.service_class}-${i}`} className="border-b border-border/50 hover:bg-panel/50">
                    <td className="px-4 py-2 font-mono">{b.service_name}</td>
                    <td className="px-4 py-2 text-muted">{b.class_name}</td>
                    <td className="px-4 py-2 text-right tabular-nums">{fmtNumber(b.group_count)}</td>
                    <td className="px-4 py-2 text-right tabular-nums text-muted">{fmtNumber(b.group_target)}</td>
                    <td className={cn("px-4 py-2 text-right tabular-nums", b.deficit > 0 ? "text-danger" : "")}>
                      {fmtNumber(b.deficit)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
