interface Props {
  label: string;
  value: string | number;
  color?: string;
  sub?: string;
}

export function KpiTile({ label, value, color, sub }: Props) {
  return (
    <div className="bg-card border border-border rounded-lg p-4 min-w-[140px]">
      <div className="text-muted text-[10px] uppercase tracking-wider mb-1">
        {label}
      </div>
      <div
        className="text-2xl font-bold tabular-nums"
        style={color ? { color } : undefined}
      >
        {value}
      </div>
      {sub && <div className="text-muted text-[10px] mt-1">{sub}</div>}
    </div>
  );
}
