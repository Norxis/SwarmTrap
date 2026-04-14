import { useState, useMemo } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useGodAllowlist, useWatchlist } from "../api/hooks";
import { apiPost } from "../api/client";
import { Badge, IpLink, ConfirmModal } from "../components";
import { PageLoading, ErrorDisplay } from "../components/LoadingSkeleton";
import { timeAgo } from "../lib/format";

interface GodAllowlistEntry {
  src_ip: string;
  updated_at: number;
}

const WATCHLIST_SOURCES = [
  "All",
  "god2_verdict",
  "evidence_ingest",
  "honeypot",
] as const;

export default function Allowlist() {
  const qc = useQueryClient();
  const { data: allowlistData, isLoading: alLoading, error: alError } = useGodAllowlist();
  const { data: watchlistData, isLoading: wlLoading, error: wlError } = useWatchlist(500);

  // Allowlist add form
  const [newIp, setNewIp] = useState("");
  const [adding, setAdding] = useState(false);

  // Allowlist remove confirm
  const [removeIp, setRemoveIp] = useState<string | null>(null);
  const [removing, setRemoving] = useState(false);

  // Watchlist source filter
  const [sourceFilter, setSourceFilter] = useState<string>("All");

  // --- Allowlist handlers ---

  async function handleAdd() {
    const ip = newIp.trim();
    if (!ip) return;
    setAdding(true);
    try {
      await apiPost("/data/god/allowlist/add", { ip });
      qc.invalidateQueries({ queryKey: ["god-allowlist"] });
      setNewIp("");
    } catch {
      // silently handled -- could add toast later
    } finally {
      setAdding(false);
    }
  }

  async function handleRemoveConfirm() {
    if (!removeIp) return;
    setRemoving(true);
    try {
      await apiPost("/data/god/allowlist/remove", { ip: removeIp });
      qc.invalidateQueries({ queryKey: ["god-allowlist"] });
    } catch {
      // silently handled
    } finally {
      setRemoving(false);
      setRemoveIp(null);
    }
  }

  // --- Watchlist filtered ---

  const filteredWatchlist = useMemo(() => {
    if (!watchlistData) return [];
    const list =
      sourceFilter === "All"
        ? watchlistData
        : watchlistData.filter((e) => e.source === sourceFilter);
    return list.slice(0, 100);
  }, [watchlistData, sourceFilter]);

  // --- Loading / Error ---

  if (alLoading || wlLoading) return <PageLoading />;
  if (alError) return <ErrorDisplay error={alError} />;
  if (wlError) return <ErrorDisplay error={wlError} />;

  const allowlistItems: GodAllowlistEntry[] = allowlistData?.items ?? [];

  return (
    <div className="space-y-8">
      {/* ===== Section 1: Clean Allowlist ===== */}
      <section className="space-y-3">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <h1 className="text-lg font-bold">Clean Allowlist</h1>
          <form
            className="flex items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              handleAdd();
            }}
          >
            <input
              type="text"
              value={newIp}
              onChange={(e) => setNewIp(e.target.value)}
              placeholder="IP address..."
              className="bg-card border border-border rounded px-3 py-1.5 text-xs text-text placeholder:text-muted/50 w-48 focus:outline-none focus:border-accent font-mono"
            />
            <button
              type="submit"
              disabled={adding || !newIp.trim()}
              className="px-3 py-1.5 text-xs rounded bg-ok/20 border border-ok/30 text-ok hover:bg-ok/30 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {adding ? "Adding..." : "Add"}
            </button>
          </form>
        </div>

        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-muted text-left">
                <th className="px-4 py-2 font-medium">IP</th>
                <th className="px-4 py-2 font-medium">Added</th>
                <th className="px-4 py-2 font-medium w-24 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {allowlistItems.length === 0 ? (
                <tr>
                  <td
                    colSpan={3}
                    className="px-4 py-6 text-center text-muted"
                  >
                    No entries in the allowlist
                  </td>
                </tr>
              ) : (
                allowlistItems.map((entry) => (
                  <tr
                    key={entry.src_ip}
                    className="border-b border-border/50 hover:bg-panel/30"
                  >
                    <td className="px-4 py-2">
                      <IpLink ip={entry.src_ip} />
                    </td>
                    <td className="px-4 py-2 text-muted whitespace-nowrap">
                      {timeAgo(entry.updated_at)}
                    </td>
                    <td className="px-4 py-2 text-right">
                      <button
                        onClick={() => setRemoveIp(entry.src_ip)}
                        className="text-danger hover:underline text-xs"
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <p className="text-[10px] text-muted">
          {allowlistItems.length} {allowlistItems.length === 1 ? "entry" : "entries"}
        </p>
      </section>

      {/* ===== Section 2: Watchlist Viewer ===== */}
      <section className="space-y-3">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <h1 className="text-lg font-bold">Watchlist</h1>
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="bg-card border border-border rounded px-3 py-1.5 text-xs text-text focus:outline-none focus:border-accent"
          >
            {WATCHLIST_SOURCES.map((s) => (
              <option key={s} value={s}>
                {s === "All" ? "All Sources" : s}
              </option>
            ))}
          </select>
        </div>

        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-muted text-left">
                <th className="px-4 py-2 font-medium">IP</th>
                <th className="px-4 py-2 font-medium">Source</th>
                <th className="px-4 py-2 font-medium">Reason</th>
                <th className="px-4 py-2 font-medium">Updated</th>
              </tr>
            </thead>
            <tbody>
              {filteredWatchlist.length === 0 ? (
                <tr>
                  <td
                    colSpan={4}
                    className="px-4 py-6 text-center text-muted"
                  >
                    No watchlist entries
                  </td>
                </tr>
              ) : (
                filteredWatchlist.map((entry) => (
                  <tr
                    key={entry.ip}
                    className="border-b border-border/50 hover:bg-panel/30"
                  >
                    <td className="px-4 py-2">
                      <IpLink ip={entry.ip} />
                    </td>
                    <td className="px-4 py-2">
                      {entry.source ? (
                        <Badge variant="muted">{entry.source}</Badge>
                      ) : (
                        <span className="text-muted">--</span>
                      )}
                    </td>
                    <td className="px-4 py-2">
                      <span
                        className="truncate max-w-[240px] inline-block"
                        title={entry.reason ?? ""}
                      >
                        {entry.reason || "--"}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-muted whitespace-nowrap">
                      {timeAgo(entry.updated_at_epoch)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <p className="text-[10px] text-muted">
          Showing {filteredWatchlist.length} of {watchlistData?.length ?? 0} entries
          {sourceFilter !== "All" && ` (filtered: ${sourceFilter})`}
        </p>
      </section>

      {/* ===== Remove Confirm Modal ===== */}
      <ConfirmModal
        open={removeIp !== null}
        title="Remove from Allowlist"
        message={`Remove ${removeIp} from the clean allowlist? The GOD pipeline will resume scoring this IP.`}
        confirmLabel={removing ? "Removing..." : "Remove"}
        onConfirm={handleRemoveConfirm}
        onCancel={() => setRemoveIp(null)}
      />
    </div>
  );
}
