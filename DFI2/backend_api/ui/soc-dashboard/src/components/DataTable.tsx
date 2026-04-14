import { useState, useMemo, type ReactNode } from "react";

export interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  sortFn?: (a: T, b: T) => number;
  width?: string;
}

interface Props<T> {
  columns: Column<T>[];
  data: T[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  emptyText?: string;
}

export function DataTable<T>({
  columns,
  data,
  rowKey,
  onRowClick,
  emptyText = "No data",
}: Props<T>) {
  const [sortCol, setSortCol] = useState<string | null>(null);
  const [sortAsc, setSortAsc] = useState(true);

  const sorted = useMemo(() => {
    if (!sortCol) return data;
    const col = columns.find((c) => c.key === sortCol);
    if (!col?.sortFn) return data;
    const arr = [...data];
    arr.sort((a, b) => (sortAsc ? col.sortFn!(a, b) : col.sortFn!(b, a)));
    return arr;
  }, [data, sortCol, sortAsc, columns]);

  function handleSort(key: string) {
    if (sortCol === key) {
      setSortAsc(!sortAsc);
    } else {
      setSortCol(key);
      setSortAsc(true);
    }
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-border text-muted">
            {columns.map((c) => (
              <th
                key={c.key}
                className="text-left px-3 py-2 font-medium whitespace-nowrap select-none"
                style={c.width ? { width: c.width } : undefined}
                onClick={c.sortFn ? () => handleSort(c.key) : undefined}
                role={c.sortFn ? "button" : undefined}
              >
                {c.header}
                {sortCol === c.key && (
                  <span className="ml-1">{sortAsc ? "\u25B2" : "\u25BC"}</span>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.length === 0 && (
            <tr>
              <td
                colSpan={columns.length}
                className="text-center text-muted py-8"
              >
                {emptyText}
              </td>
            </tr>
          )}
          {sorted.map((row) => (
            <tr
              key={rowKey(row)}
              className="border-b border-border/50 hover:bg-card/60 transition-colors"
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              style={onRowClick ? { cursor: "pointer" } : undefined}
            >
              {columns.map((c) => (
                <td key={c.key} className="px-3 py-2">
                  {c.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
