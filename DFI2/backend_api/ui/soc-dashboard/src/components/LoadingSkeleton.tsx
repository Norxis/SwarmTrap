export function LoadingSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-3 p-4">
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="h-4 bg-card rounded animate-pulse"
          style={{ width: `${60 + Math.random() * 40}%` }}
        />
      ))}
    </div>
  );
}

export function PageLoading() {
  return (
    <div className="flex items-center justify-center h-64 text-muted text-xs">
      Loading...
    </div>
  );
}

export function ErrorDisplay({ error }: { error: unknown }) {
  const msg =
    error instanceof Error ? error.message : "An unknown error occurred";
  return (
    <div className="border border-danger/30 bg-danger/10 rounded-lg p-4 text-danger text-xs">
      {msg}
    </div>
  );
}
