import { cn } from "../lib/format";

const variants: Record<string, string> = {
  depth0: "bg-depth-0/20 text-depth-0 border-depth-0/30",
  depth1: "bg-depth-1/20 text-depth-1 border-depth-1/30",
  depth2: "bg-depth-2/20 text-depth-2 border-depth-2/30",
  depth3: "bg-danger/20 text-danger border-danger/30",
  p1: "bg-danger/20 text-danger border-danger/30",
  p2: "bg-warn/20 text-warn border-warn/30",
  p3: "bg-accent/20 text-accent border-accent/30",
  ok: "bg-ok/20 text-ok border-ok/30",
  warn: "bg-warn/20 text-warn border-warn/30",
  danger: "bg-danger/20 text-danger border-danger/30",
  muted: "bg-muted/20 text-muted border-muted/30",
  accent: "bg-accent/20 text-accent border-accent/30",
};

export function Badge({
  variant = "muted",
  children,
  className,
}: {
  variant?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-block border rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider whitespace-nowrap",
        variants[variant] ?? variants.muted,
        className,
      )}
    >
      {children}
    </span>
  );
}

export function DepthBadge({ depth }: { depth: number }) {
  return <Badge variant={`depth${depth}`}>D{depth}</Badge>;
}

export function PriorityBadge({ priority }: { priority: number }) {
  return <Badge variant={`p${priority}`}>P{priority}</Badge>;
}

export function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span
      className={cn(
        "inline-block w-2 h-2 rounded-full",
        ok ? "bg-ok" : "bg-danger",
      )}
    />
  );
}
