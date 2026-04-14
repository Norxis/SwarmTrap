import { useState } from "react";
import { useVMs, useVMEvents } from "../api/hooks";
// reboot removed
import type { VMStatus as VMStatusType, VMEvent } from "../api/types";
import {
  StatusDot,
  Badge,
} from "../components";
import { PageLoading, ErrorDisplay } from "../components/LoadingSkeleton";
import { fmtTs, fmtUptime, fmtNumber } from "../lib/format";
import { cn } from "../lib/format";

export default function VMStatusPage() {
  const vms = useVMs();

  if (vms.isLoading) return <PageLoading />;
  if (vms.error) return <ErrorDisplay error={vms.error} />;

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-bold">VM Status</h1>

      {/* VM Grid */}
      <div className="grid gap-4" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(380px, 1fr))" }}>
        {(vms.data ?? []).map((vm) => (
          <VMCard key={vm.vmid} vm={vm} />
        ))}
      </div>

      {!vms.data?.length && (
        <div className="text-xs text-muted text-center py-8">
          No VMs found
        </div>
      )}
    </div>
  );
}

// ── VM Card ──

function VMCard({ vm }: { vm: VMStatusType }) {
  const [showEvents, setShowEvents] = useState(false);

  const isRunning = vm.status === "running";
  const ramPct =
    vm.ram_total_mb > 0
      ? ((vm.ram_used_mb / vm.ram_total_mb) * 100).toFixed(1)
      : "0";

  return (
    <div className="bg-card border border-border rounded-lg p-4 space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <StatusDot ok={isRunning} />
          <h3 className="text-sm font-bold">{vm.name}</h3>
          <Badge variant={isRunning ? "ok" : "danger"}>{vm.status}</Badge>
        </div>
        <span className="text-[10px] text-muted">VMID {vm.vmid}</span>
      </div>

      {/* Details */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
        <div>
          <span className="text-muted">OS:</span>{" "}
          <span>{vm.os || "--"}</span>
        </div>
        <div>
          <span className="text-muted">LAN:</span>{" "}
          <span className="font-mono">{vm.lan_ip || "--"}</span>
        </div>
        <div>
          <span className="text-muted">CPU:</span>{" "}
          <span className="tabular-nums">{vm.cpu_pct.toFixed(1)}%</span>
        </div>
        <div>
          <span className="text-muted">Pub:</span>{" "}
          <span className="font-mono">{vm.pub_ip || "--"}</span>
        </div>
        <div>
          <span className="text-muted">Uptime:</span>{" "}
          <span>{vm.uptime_s > 0 ? fmtUptime(vm.uptime_s) : "--"}</span>
        </div>
        <div>
          <span className="text-muted">Services:</span>{" "}
          <span>{vm.services || "--"}</span>
        </div>
      </div>

      {/* RAM bar */}
      <div>
        <div className="flex justify-between text-[10px] text-muted mb-1">
          <span>RAM</span>
          <span>
            {fmtNumber(vm.ram_used_mb)} / {fmtNumber(vm.ram_total_mb)} MB ({ramPct}%)
          </span>
        </div>
        <div className="h-1.5 bg-panel rounded-full overflow-hidden">
          <div
            className={cn(
              "h-full rounded-full transition-all",
              Number(ramPct) > 90
                ? "bg-danger"
                : Number(ramPct) > 70
                  ? "bg-warn"
                  : "bg-accent",
            )}
            style={{ width: `${Math.min(Number(ramPct), 100)}%` }}
          />
        </div>
      </div>

      {/* Stats */}
      <div className="flex gap-4 text-xs">
        <div>
          <span className="text-muted">Flows 24h:</span>{" "}
          <span className="tabular-nums">{fmtNumber(vm.flows_24h)}</span>
        </div>
        <div>
          <span className="text-muted">Attackers 24h:</span>{" "}
          <span className="tabular-nums text-danger">{fmtNumber(vm.attackers_24h)}</span>
        </div>
      </div>

      {/* Action buttons */}
      <div className="flex gap-2 pt-1 border-t border-border/50">
        <button
          className="px-3 py-1 text-[10px] rounded border border-border text-muted hover:bg-panel hover:text-text"
          onClick={() => setShowEvents(!showEvents)}
        >
          {showEvents ? "Hide Events" : "Show Events"}
        </button>
      </div>

      {/* Events panel */}
      {showEvents && <VMEventsPanel vmid={vm.vmid} />}
    </div>
  );
}

// ── VM Events Panel ──

function VMEventsPanel({ vmid }: { vmid: number }) {
  const { data, isLoading, error } = useVMEvents(vmid);

  if (isLoading) {
    return (
      <div className="text-[10px] text-muted py-2">Loading events...</div>
    );
  }

  if (error) {
    return (
      <div className="text-[10px] text-danger py-2">
        Failed to load events
      </div>
    );
  }

  if (!data || data.length === 0) {
    return (
      <div className="text-[10px] text-muted py-2">No recent events</div>
    );
  }

  return (
    <div className="border-t border-border/50 pt-2 max-h-48 overflow-y-auto space-y-1">
      <h4 className="text-[10px] text-muted uppercase tracking-wider mb-1">
        Events ({data.length})
      </h4>
      {data.map((evt: VMEvent, i: number) => (
        <div
          key={`${evt.ts}-${i}`}
          className="flex gap-2 text-[10px] border-b border-border/20 pb-1"
        >
          <span className="text-muted whitespace-nowrap shrink-0">
            {fmtTs(evt.ts)}
          </span>
          <span className="font-mono text-accent shrink-0">{evt.src_ip}</span>
          <Badge variant={evt.event_type.includes("attack") ? "danger" : "muted"}>
            {evt.event_type}
          </Badge>
          <span className="text-muted truncate">{evt.event_detail}</span>
          <span className="text-muted/50 shrink-0">[{evt.source_log}]</span>
        </div>
      ))}
    </div>
  );
}
