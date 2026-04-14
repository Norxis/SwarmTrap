import { useState, useMemo } from "react";
import { useAuditLog } from "../api/hooks";
import type { AuditRow } from "../api/types";
import {
  DataTable,
  type Column,
  Badge,
  IpLink,
} from "../components";
import { PageLoading, ErrorDisplay } from "../components/LoadingSkeleton";
import { fmtTs } from "../lib/format";

function actionVariant(action: string): string {
  if (action.includes("delete")) return "danger";
  if (action.includes("upsert")) return "ok";
  if (action.includes("annotate")) return "accent";
  if (action.includes("promote")) return "warn";
  if (action.includes("demote")) return "muted";
  return "muted";
}

export default function AuditLog() {
  const { data, isLoading, error } = useAuditLog(200);
  const [search, setSearch] = useState("");

  const filtered = useMemo(() => {
    if (!data) return [];
    if (!search.trim()) return data;
    const q = search.toLowerCase();
    return data.filter(
      (r) =>
        r.ip.toLowerCase().includes(q) ||
        r.request_id.toLowerCase().includes(q),
    );
  }, [data, search]);

  const columns: Column<AuditRow>[] = [
    {
      key: "timestamp",
      header: "Timestamp",
      render: (r) => (
        <span className="text-muted whitespace-nowrap">{fmtTs(r.timestamp)}</span>
      ),
      sortFn: (a, b) => a.timestamp - b.timestamp,
    },
    {
      key: "ip",
      header: "IP",
      render: (r) => <IpLink ip={r.ip} />,
      sortFn: (a, b) => a.ip.localeCompare(b.ip),
    },
    {
      key: "action",
      header: "Action",
      render: (r) => <Badge variant={actionVariant(r.action)}>{r.action}</Badge>,
      sortFn: (a, b) => a.action.localeCompare(b.action),
    },
    {
      key: "old_val",
      header: "Old Val",
      render: (r) => (
        <span className="text-muted text-[10px] font-mono truncate max-w-[120px] inline-block">
          {r.old_val || "--"}
        </span>
      ),
    },
    {
      key: "new_val",
      header: "New Val",
      render: (r) => (
        <span className="text-[10px] font-mono truncate max-w-[120px] inline-block">
          {r.new_val || "--"}
        </span>
      ),
    },
    {
      key: "actor",
      header: "Actor",
      render: (r) => (
        <Badge variant="muted">{r.actor || "system"}</Badge>
      ),
    },
    {
      key: "reason",
      header: "Reason",
      render: (r) => (
        <span className="text-xs truncate max-w-[180px] inline-block" title={r.reason}>
          {r.reason || "--"}
        </span>
      ),
    },
    {
      key: "request_id",
      header: "Request ID",
      render: (r) => (
        <span className="text-[10px] text-muted font-mono truncate max-w-[100px] inline-block" title={r.request_id}>
          {r.request_id ? r.request_id.slice(0, 8) : "--"}
        </span>
      ),
    },
    {
      key: "source",
      header: "Source",
      render: (r) =>
        r.source ? (
          <Badge variant="muted">{r.source}</Badge>
        ) : (
          <span className="text-muted">--</span>
        ),
    },
  ];

  if (isLoading) return <PageLoading />;
  if (error) return <ErrorDisplay error={error} />;

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-bold">Audit Log</h1>

      {/* Search */}
      <div className="flex items-center gap-3">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter by IP or Request ID..."
          className="bg-card border border-border rounded px-3 py-1.5 text-xs text-text placeholder:text-muted/50 w-72 focus:outline-none focus:border-accent"
        />
        <span className="text-xs text-muted">
          {filtered.length} of {data?.length ?? 0} entries
        </span>
      </div>

      {/* Table */}
      <div className="bg-card border border-border rounded-lg p-4">
        <DataTable
          columns={columns}
          data={filtered}
          rowKey={(r) => `${r.request_id}:${r.ip}:${r.timestamp}`}
          emptyText="No audit entries found"
        />
      </div>
    </div>
  );
}
