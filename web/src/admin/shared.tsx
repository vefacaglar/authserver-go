import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { Search } from "lucide-react";
import { apiGet } from "../lib/api";
import { errorMessage } from "../components/ui";
import type { Paged } from "../lib/types";

// --- toasts ---

interface Toast {
  id: number;
  message: string;
  kind: "success" | "error";
}

const ToastContext = createContext<(message: string, kind?: "success" | "error") => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);

  const push = useCallback((message: string, kind: "success" | "error" = "success") => {
    const id = nextId.current++;
    setToasts((t) => [...t, { id, message, kind }]);
    window.setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3500);
  }, []);

  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="fixed bottom-4 right-4 z-[60] flex flex-col gap-2 max-w-sm w-full px-4">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={
              t.kind === "error"
                ? "border border-red-900 bg-red-950/90 text-red-300 px-4 py-3 text-xs lowercase"
                : "border border-zinc-700 bg-zinc-300 text-zinc-950 px-4 py-3 text-xs font-bold lowercase"
            }
          >
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext);
}

// --- list plumbing ---

export function usePagedList<T>(path: string, pageSize = 25) {
  const [items, setItems] = useState<T[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    async (p: number) => {
      setLoading(true);
      setError(null);
      try {
        const sep = path.includes("?") ? "&" : "?";
        const r = await apiGet<Paged<T>>(`${path}${sep}page=${p}&page_size=${pageSize}`);
        setItems(r.items ?? []);
        setTotal(r.total_count ?? 0);
        setPage(p);
      } catch (e) {
        setError(errorMessage(e));
      } finally {
        setLoading(false);
      }
    },
    [path, pageSize],
  );

  useEffect(() => {
    void load(1);
  }, [load]);

  return { items, total, page, pageSize, loading, error, load, reload: () => load(page) };
}

export function Pagination({
  page,
  pageSize,
  total,
  onPage,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPage: (p: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (pages <= 1) return null;
  return (
    <div className="flex items-center justify-between mt-4 text-xs lowercase">
      <span className="text-zinc-500">
        page {page} of {pages} — {total} total
      </span>
      <div className="flex gap-2">
        <button type="button" className="admin-btn admin-btn-ghost" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          ← prev
        </button>
        <button
          type="button"
          className="admin-btn admin-btn-ghost"
          disabled={page >= pages}
          onClick={() => onPage(page + 1)}
        >
          next →
        </button>
      </div>
    </div>
  );
}

export function ListHeader({
  search,
  onSearch,
  searchPlaceholder,
  action,
}: {
  search?: string;
  onSearch?: (v: string) => void;
  searchPlaceholder?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
      {onSearch ? (
        <div className="relative max-w-sm flex-1">
          <Search className="absolute left-2.5 top-2.5 w-4 h-4 text-zinc-600" />
          <input
            type="text"
            placeholder={searchPlaceholder ?? "search…"}
            className="admin-input pl-8"
            value={search ?? ""}
            onChange={(e) => onSearch(e.target.value)}
          />
        </div>
      ) : (
        <div />
      )}
      {action}
    </div>
  );
}

export function DataTable({ head, children }: { head: ReactNode; children: ReactNode }) {
  return (
    <div className="bg-[#1a1a1a] border border-zinc-800/60 mt-4">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-zinc-800/60 text-zinc-500 text-xs lowercase tracking-wide">{head}</tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/40 text-sm">{children}</tbody>
        </table>
      </div>
    </div>
  );
}

export function Th({ children, right = false }: { children?: ReactNode; right?: boolean }) {
  return <th className={`p-4 font-normal ${right ? "text-right" : ""}`}>{children}</th>;
}

export function Badge({ tone, children }: { tone: "zinc" | "emerald" | "red" | "amber"; children: ReactNode }) {
  const tones: Record<string, string> = {
    zinc: "bg-zinc-800/60 text-zinc-400 border border-zinc-700/60",
    emerald: "bg-emerald-950/40 text-emerald-400 border border-emerald-900/60",
    red: "bg-red-950/40 text-red-400 border border-red-900/60",
    amber: "bg-amber-950/40 text-amber-400 border border-amber-900/60",
  };
  return <span className={`px-2 py-0.5 text-xs lowercase ${tones[tone]}`}>{children}</span>;
}

// ClaimsEditor edits a Type/Value claim list (user and role claims
// share the wire shape — capitalised keys, matching the Go structs).
export interface ClaimRow {
  Type: string;
  Value: string;
}

export function ClaimsEditor({
  rows,
  onChange,
}: {
  rows: ClaimRow[];
  onChange: (rows: ClaimRow[]) => void;
}) {
  const set = (i: number, patch: Partial<ClaimRow>) =>
    onChange(rows.map((r, j) => (i === j ? { ...r, ...patch } : r)));
  return (
    <div className="space-y-3">
      {rows.map((r, i) => (
        <div key={i} className="flex gap-2 items-center">
          <input
            type="text"
            placeholder="type (e.g. name, locale)"
            className="admin-input w-1/3"
            value={r.Type}
            onChange={(e) => set(i, { Type: e.target.value })}
          />
          <input
            type="text"
            placeholder="value"
            className="admin-input flex-1"
            value={r.Value}
            onChange={(e) => set(i, { Value: e.target.value })}
          />
          <button
            type="button"
            className="admin-btn admin-btn-danger"
            onClick={() => onChange(rows.filter((_, j) => j !== i))}
          >
            remove
          </button>
        </div>
      ))}
      <button type="button" className="admin-btn admin-btn-ghost" onClick={() => onChange([...rows, { Type: "", Value: "" }])}>
        + add claim
      </button>
    </div>
  );
}
