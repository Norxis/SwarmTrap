import { useState, useMemo } from "react";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";

import { useGodMapEvents } from "../api/hooks";
import type { GodMapAttacker } from "../api/types";
import { fmtNumber } from "../lib/format";
import { IpLink } from "../components/IpLink";
import { Badge } from "../components/Badge";
import { DataTable, type Column } from "../components/DataTable";
import { ErrorDisplay } from "../components/LoadingSkeleton";

/* ---- helpers ---- */

const TIME_RANGES: { label: string; hours: number }[] = [
  { label: "1h", hours: 1 },
  { label: "6h", hours: 6 },
  { label: "24h", hours: 24 },
  { label: "7d", hours: 168 },
];

function countryFlag(code: string): string {
  if (!code || code.length !== 2) return "";
  return String.fromCodePoint(
    ...[...code.toUpperCase()].map((c) => 0x1f1e6 - 65 + c.charCodeAt(0)),
  );
}

function classColor(xgbClass: number): string {
  switch (xgbClass) {
    case 0: return "#58a6ff"; // RECON (blue)
    case 1: return "#e3b341"; // KNOCK (yellow)
    case 2: return "#f0883e"; // BRUTE (orange)
    case 3: return "#f85149"; // EXPLOIT (red)
    default: return "#8b949e";
  }
}

function classVariant(xgbClass: number): string {
  switch (xgbClass) {
    case 0: return "accent";
    case 1: return "warn";
    case 2: return "warn";
    case 3: return "danger";
    default: return "accent";
  }
}

function markerRadius(flows: number): number {
  return Math.min(20, Math.max(4, Math.log2(flows + 1) * 2.5));
}

/* ---- top country helper ---- */

function topCountry(attackers: GodMapAttacker[]): string {
  const counts: Record<string, number> = {};
  for (const a of attackers) {
    if (a.country_code) {
      counts[a.country_code] = (counts[a.country_code] || 0) + a.flow_count;
    }
  }
  let best = "";
  let max = 0;
  for (const [cc, n] of Object.entries(counts)) {
    if (n > max) {
      max = n;
      best = cc;
    }
  }
  return best ? `${countryFlag(best)} ${best}` : "--";
}

function totalFlows(attackers: GodMapAttacker[]): number {
  let sum = 0;
  for (const a of attackers) sum += a.flow_count;
  return sum;
}

/* ---- table columns ---- */

const columns: Column<GodMapAttacker>[] = [
  {
    key: "src_ip",
    header: "IP",
    render: (r) => <IpLink ip={r.src_ip} />,
  },
  {
    key: "country",
    header: "Country",
    render: (r) => (
      <span>
        {countryFlag(r.country_code)} {r.country || r.country_code || "--"}
      </span>
    ),
    sortFn: (a, b) => (a.country || "").localeCompare(b.country || ""),
  },
  {
    key: "xgb_class",
    header: "Class",
    render: (r) => <Badge variant={classVariant(r.xgb_class)}>{r.xgb_class_name}</Badge>,
    sortFn: (a, b) => a.xgb_class - b.xgb_class,
  },
  {
    key: "flow_count",
    header: "Flows",
    render: (r) => <span className="tabular-nums">{fmtNumber(r.flow_count)}</span>,
    sortFn: (a, b) => a.flow_count - b.flow_count,
  },
];

/* ---- dark popup styles (injected once) ---- */

const DARK_POPUP_CSS = `
.leaflet-popup-content-wrapper {
  background: #161b22 !important;
  color: #e6edf3 !important;
  border: 1px solid #30363d !important;
  border-radius: 8px !important;
  box-shadow: 0 4px 12px rgba(0,0,0,0.5) !important;
  font-family: "SF Mono", "Consolas", "Liberation Mono", "Menlo", monospace !important;
  font-size: 12px !important;
}
.leaflet-popup-tip {
  background: #161b22 !important;
  border: 1px solid #30363d !important;
}
.leaflet-popup-close-button {
  color: #8b949e !important;
}
.leaflet-popup-close-button:hover {
  color: #e6edf3 !important;
}
.leaflet-control-zoom a {
  background: #161b22 !important;
  color: #e6edf3 !important;
  border-color: #30363d !important;
}
.leaflet-control-zoom a:hover {
  background: #21262d !important;
}
.leaflet-control-attribution {
  background: rgba(13,17,23,0.8) !important;
  color: #8b949e !important;
  font-size: 9px !important;
}
.leaflet-control-attribution a {
  color: #58a6ff !important;
}
`;

/* ---- main component ---- */

export default function AttackMap() {
  const [hours, setHours] = useState(1);
  const [panelOpen, setPanelOpen] = useState(true);
  const { data, isLoading, error } = useGodMapEvents(hours, 500);

  const attackers = useMemo(
    () => (data?.events ?? []).filter((a) => a.lat !== 0 || a.lng !== 0),
    [data],
  );

  if (error) {
    return (
      <div className="p-4">
        <ErrorDisplay error={error} />
      </div>
    );
  }

  return (
    <div className="flex flex-col h-[calc(100vh-3rem)] -m-4">
      {/* injected dark popup styles */}
      <style>{DARK_POPUP_CSS}</style>

      {/* ---- stats bar ---- */}
      <div className="flex items-center gap-4 px-4 py-2 bg-panel border-b border-border shrink-0">
        <div className="flex items-center gap-3">
          {TIME_RANGES.map((tr) => (
            <button
              key={tr.hours}
              onClick={() => setHours(tr.hours)}
              className={`px-2.5 py-1 text-xs rounded transition-colors ${
                hours === tr.hours
                  ? "bg-accent/20 text-accent border border-accent/30"
                  : "text-muted hover:text-text hover:bg-card/60"
              }`}
            >
              {tr.label}
            </button>
          ))}
        </div>

        <div className="h-4 w-px bg-border" />

        <div className="flex items-center gap-4 text-xs">
          <span>
            <span className="text-muted">Attackers: </span>
            <span className="text-accent font-bold tabular-nums">
              {fmtNumber(attackers.length)}
            </span>
          </span>
          <span>
            <span className="text-muted">Flows: </span>
            <span className="text-warn font-bold tabular-nums">
              {fmtNumber(totalFlows(attackers))}
            </span>
          </span>
          <span>
            <span className="text-muted">Top: </span>
            <span className="font-bold">{topCountry(attackers)}</span>
          </span>
        </div>

        <div className="ml-auto flex items-center gap-2">
          {isLoading && (
            <span className="text-[10px] text-muted animate-pulse">
              Loading...
            </span>
          )}
          <button
            onClick={() => setPanelOpen(!panelOpen)}
            className="px-2.5 py-1 text-xs text-muted hover:text-text hover:bg-card/60 rounded transition-colors"
          >
            {panelOpen ? "Hide Table" : "Show Table"}
          </button>
        </div>
      </div>

      {/* ---- map ---- */}
      <div className="flex-1 relative min-h-0">
        <MapContainer
          center={[20, 0]}
          zoom={2}
          className="w-full h-full"
          style={{ background: "#0d1117" }}
          zoomControl={true}
          attributionControl={true}
        >
          <TileLayer
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/attributions">CARTO</a>'
          />

          {/* attacker markers */}
          {attackers.map((a) => (
            <CircleMarker
              key={a.src_ip}
              center={[a.lat, a.lng]}
              radius={markerRadius(a.flow_count)}
              pathOptions={{
                color: classColor(a.xgb_class),
                fillColor: classColor(a.xgb_class),
                fillOpacity: 0.5,
                weight: 1.5,
              }}
            >
              <Popup>
                <div className="space-y-1.5 min-w-[180px]">
                  <div className="font-bold">{a.src_ip}</div>
                  <div>
                    {countryFlag(a.country_code)}{" "}
                    {a.country || a.country_code || "Unknown"}
                  </div>
                  <div>
                    <span
                      style={{
                        color: classColor(a.xgb_class),
                        fontWeight: 700,
                      }}
                    >
                      {a.xgb_class_name}
                    </span>
                  </div>
                  <div>
                    <span style={{ color: "#8b949e" }}>Flows: </span>
                    {fmtNumber(a.flow_count)}
                  </div>
                </div>
              </Popup>
            </CircleMarker>
          ))}
        </MapContainer>

        {/* legend overlay */}
        <div className="absolute bottom-3 left-3 z-[1000] bg-panel/90 border border-border rounded-lg px-3 py-2 text-[10px] space-y-1 backdrop-blur-sm">
          <div className="text-muted uppercase tracking-wider font-bold mb-1">
            Legend
          </div>
          <div className="flex items-center gap-2">
            <span
              className="inline-block w-2.5 h-2.5 rounded-full"
              style={{ background: "#58a6ff" }}
            />
            <span>RECON</span>
          </div>
          <div className="flex items-center gap-2">
            <span
              className="inline-block w-2.5 h-2.5 rounded-full"
              style={{ background: "#e3b341" }}
            />
            <span>KNOCK</span>
          </div>
          <div className="flex items-center gap-2">
            <span
              className="inline-block w-2.5 h-2.5 rounded-full"
              style={{ background: "#f0883e" }}
            />
            <span>BRUTE</span>
          </div>
          <div className="flex items-center gap-2">
            <span
              className="inline-block w-2.5 h-2.5 rounded-full"
              style={{ background: "#f85149" }}
            />
            <span>EXPLOIT</span>
          </div>
        </div>
      </div>

      {/* ---- bottom panel ---- */}
      {panelOpen && (
        <div className="shrink-0 h-64 border-t border-border bg-panel overflow-auto">
          <DataTable
            columns={columns}
            data={attackers}
            rowKey={(r) => r.src_ip}
            emptyText="No attackers in this time range"
          />
        </div>
      )}
    </div>
  );
}
