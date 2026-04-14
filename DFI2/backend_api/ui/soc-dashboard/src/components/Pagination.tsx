interface Props {
  offset: number;
  limit: number;
  total: number;
  onChange: (offset: number) => void;
}

export function Pagination({ offset, limit, total, onChange }: Props) {
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.ceil(total / limit);

  if (pages <= 1) return null;

  return (
    <div className="flex items-center gap-3 text-xs text-muted py-2">
      <button
        className="px-2 py-1 rounded border border-border hover:bg-card disabled:opacity-30"
        disabled={page <= 1}
        onClick={() => onChange(offset - limit)}
      >
        Prev
      </button>
      <span>
        Page {page} of {pages} ({total} total)
      </span>
      <button
        className="px-2 py-1 rounded border border-border hover:bg-card disabled:opacity-30"
        disabled={page >= pages}
        onClick={() => onChange(offset + limit)}
      >
        Next
      </button>
    </div>
  );
}
