import { NavLink } from "react-router-dom";
import { cn } from "../lib/format";

interface NavItem {
  to: string;
  label: string;
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

const navGroups: NavGroup[] = [
  {
    title: "GOD Pipeline",
    items: [
      { to: "/", label: "Home" },
      { to: "/verdicts", label: "Verdicts" },
      { to: "/services", label: "Services" },
      { to: "/map", label: "Attack Map" },
    ],
  },
  {
    title: "Intelligence",
    items: [
      { to: "/training", label: "Training & Models" },
    ],
  },
];

export function Sidebar() {
  return (
    <aside className="w-52 bg-panel border-r border-border flex flex-col h-screen sticky top-0 shrink-0">
      <div className="px-4 py-4 border-b border-border">
        <div className="text-sm font-bold text-accent">SwarmTrap</div>
        <div className="text-[10px] text-muted">Live Intelligence</div>
      </div>
      <nav className="flex-1 overflow-y-auto py-2">
        {navGroups.map((g) => (
          <div key={g.title} className="mb-2">
            <div className="px-4 py-1 text-[10px] text-muted uppercase tracking-wider">
              {g.title}
            </div>
            {g.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === "/"}
                className={({ isActive }) =>
                  cn(
                    "block px-4 py-1.5 text-xs hover:bg-card/60 transition-colors",
                    isActive && "bg-card text-accent border-l-2 border-accent",
                  )
                }
              >
                {item.label}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
      <div className="px-3 py-3 border-t border-border space-y-2">
        <a href="/" className="block text-xs text-center py-1.5 rounded border border-border text-muted hover:text-accent hover:border-accent transition-colors">
          &larr; Back to Site
        </a>
        <a href="/join" className="block text-xs text-center py-1.5 rounded bg-accent/20 text-accent font-semibold hover:bg-accent hover:text-[#0d1117] transition-colors">
          Join SwarmTrap
        </a>
      </div>
    </aside>
  );
}
