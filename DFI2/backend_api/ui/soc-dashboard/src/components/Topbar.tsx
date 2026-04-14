import { useState, useCallback, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { healthCheck, setApiKey, setBasicAuth } from "../api/client";
import { cn } from "../lib/format";

type ConnStatus = "connected" | "stale" | "error" | "checking";

export function Topbar() {
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState<ConnStatus>("checking");
  const [showSettings, setShowSettings] = useState(false);
  const lastOk = useRef<number>(0);

  useEffect(() => {
    const check = async () => {
      const ok = await healthCheck();
      if (ok) {
        lastOk.current = Date.now();
        setStatus("connected");
      } else if (lastOk.current > 0 && Date.now() - lastOk.current < 60_000) {
        setStatus("stale");
      } else {
        setStatus("error");
      }
    };
    check();
    const id = setInterval(check, 5000);
    return () => clearInterval(id);
  }, []);

  const handleSearch = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      const ip = search.trim();
      if (ip) {
        navigate(`/ip/${ip}`);
        setSearch("");
      }
    },
    [search, navigate],
  );

  return (
    <header className="bg-panel border-b border-border px-4 py-2 flex items-center gap-4 sticky top-0 z-40">
      <div
        className="flex items-center gap-1.5 px-2 py-1 rounded bg-card/60 border border-border"
        title={
          status === "connected"
            ? "API responding normally"
            : status === "stale"
              ? "API response delayed (>60s)"
              : status === "error"
                ? "API unreachable"
                : "Checking connection..."
        }
      >
        <span
          className={cn(
            "w-2 h-2 rounded-full",
            status === "connected" && "bg-ok",
            status === "stale" && "bg-warn",
            status === "error" && "bg-danger animate-pulse",
            status === "checking" && "bg-muted animate-pulse",
          )}
        />
        <span
          className={cn(
            "text-[10px] font-medium",
            status === "connected" && "text-ok",
            status === "stale" && "text-warn",
            status === "error" && "text-danger",
            status === "checking" && "text-muted",
          )}
        >
          {status === "connected"
            ? "Connected"
            : status === "stale"
              ? "Stale"
              : status === "error"
                ? "Disconnected"
                : "Connecting..."}
        </span>
      </div>

      <form onSubmit={handleSearch} className="flex-1 max-w-md">
        <input
          type="text"
          placeholder="Search IP..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full bg-card border border-border rounded px-3 py-1.5 text-xs text-text placeholder:text-muted focus:outline-none focus:border-accent"
        />
      </form>

      <div className="ml-auto flex items-center gap-2">
        <button
          className="text-xs text-muted hover:text-text px-2 py-1 rounded border border-border hover:bg-card"
          onClick={() => setShowSettings(!showSettings)}
        >
          Settings
        </button>
      </div>

      {showSettings && (
        <SettingsPanel onClose={() => setShowSettings(false)} />
      )}
    </header>
  );
}

function SettingsPanel({ onClose }: { onClose: () => void }) {
  const [apiKey, setKey] = useState(
    localStorage.getItem("soc_api_key") ?? "",
  );
  const [user, setUser] = useState("admin");
  const [pass, setPass] = useState("");

  function saveApiKey() {
    setApiKey(apiKey);
    onClose();
  }

  function saveBasic() {
    setBasicAuth(user, pass);
    onClose();
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 bg-black/50">
      <div className="bg-panel border border-border rounded-lg p-6 w-96">
        <h3 className="text-sm font-bold mb-4">Authentication Settings</h3>

        <div className="space-y-4">
          <div>
            <label className="text-[10px] text-muted uppercase">API Key</label>
            <div className="flex gap-2 mt-1">
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setKey(e.target.value)}
                className="flex-1 bg-card border border-border rounded px-2 py-1 text-xs"
                placeholder="X-API-Key"
              />
              <button
                className="px-2 py-1 text-xs rounded bg-accent/20 text-accent border border-accent/30"
                onClick={saveApiKey}
              >
                Save
              </button>
            </div>
          </div>

          <div>
            <label className="text-[10px] text-muted uppercase">
              HTTP Basic Auth
            </label>
            <div className="flex gap-2 mt-1">
              <input
                type="text"
                value={user}
                onChange={(e) => setUser(e.target.value)}
                className="w-24 bg-card border border-border rounded px-2 py-1 text-xs"
                placeholder="User"
              />
              <input
                type="password"
                value={pass}
                onChange={(e) => setPass(e.target.value)}
                className="flex-1 bg-card border border-border rounded px-2 py-1 text-xs"
                placeholder="Password"
              />
              <button
                className="px-2 py-1 text-xs rounded bg-accent/20 text-accent border border-accent/30"
                onClick={saveBasic}
              >
                Save
              </button>
            </div>
          </div>
        </div>

        <button
          className="mt-4 text-xs text-muted hover:text-text"
          onClick={onClose}
        >
          Close
        </button>
      </div>
    </div>
  );
}
