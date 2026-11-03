import { createContext, useCallback, useContext, useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { Check, Copy, Plus, Search, Trash2 } from "lucide-react";
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

// --- copy button ---

export function CopyButton({ value, label = "copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  async function onCopy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      // ignore clipboard errors
    }
  }

  return (
    <button
      type="button"
      onClick={() => void onCopy()}
      className="admin-btn admin-btn-ghost py-1 px-2 text-[11px]"
      title="copy to clipboard"
    >
      {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
      {copied ? "copied" : label}
    </button>
  );
}

// --- custom square toggle switch & card (replaces native browser checkboxes) ---

export function SquareToggle({
  checked,
  disabled = false,
}: {
  checked: boolean;
  disabled?: boolean;
}) {
  return (
    <span
      aria-hidden="true"
      className={`inline-flex items-center w-9 h-5 p-0.5 border transition-colors shrink-0 ${
        disabled ? "opacity-50" : ""
      } ${
        checked
          ? "bg-zinc-300 border-zinc-300 justify-end"
          : "bg-[#121212] border-zinc-700 justify-start"
      }`}
    >
      <span className={`w-3.5 h-3.5 ${checked ? "bg-zinc-950" : "bg-zinc-600"}`} />
    </span>
  );
}

export function ToggleCard({
  checked,
  onChange,
  title,
  description,
  badge,
  disabled = false,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  title: string;
  description?: string;
  badge?: ReactNode;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => !disabled && onChange(!checked)}
      className={`w-full text-left p-3.5 border transition-colors flex items-start justify-between gap-4 ${
        disabled ? "cursor-not-allowed opacity-60" : "cursor-pointer"
      } ${
        checked
          ? "bg-zinc-800/35 border-zinc-500"
          : "bg-[#121212] border-zinc-800 hover:border-zinc-700"
      }`}
    >
      <div className="min-w-0 space-y-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`text-xs font-bold lowercase ${checked ? "text-zinc-100" : "text-zinc-300"}`}>
            {title}
          </span>
          {badge}
        </div>
        {description && <p className="text-[11px] text-zinc-500 lowercase leading-relaxed">{description}</p>}
      </div>
      <SquareToggle checked={checked} disabled={disabled} />
    </button>
  );
}

// --- URI list editor (replaces raw multiline textareas) ---

export function UriListEditor({
  items,
  onChange,
  placeholder = "https://app.example.com/callback",
  presets = [],
  emptyHint = "no urls added yet.",
}: {
  items: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  presets?: Array<{ label: string; url: string }>;
  emptyHint?: string;
}) {
  const [draft, setDraft] = useState("");
  const [err, setErr] = useState<string | null>(null);

  function addUrl(raw: string) {
    const clean = raw.trim();
    if (!clean) return;
    try {
      const u = new URL(clean);
      if (!u.protocol || !u.host) {
        setErr("enter a complete url including scheme (e.g. https:// or http://localhost)");
        return;
      }
      if (u.hash) {
        setErr("oauth redirect urls cannot contain a # fragment");
        return;
      }
    } catch {
      setErr("enter a valid absolute url (e.g. https://app.example.com/callback)");
      return;
    }
    setErr(null);
    if (!items.includes(clean)) {
      onChange([...items, clean]);
    }
    setDraft("");
  }

  function onKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") {
      e.preventDefault();
      addUrl(draft);
    }
  }

  return (
    <div className="space-y-2.5">
      <div className="flex gap-2">
        <input
          type="text"
          className="input flex-1"
          placeholder={placeholder}
          value={draft}
          onChange={(e) => {
            setDraft(e.target.value);
            if (err) setErr(null);
          }}
          onKeyDown={onKeyDown}
          onBlur={() => {
            if (draft.trim()) addUrl(draft);
          }}
        />
        <button
          type="button"
          className="admin-btn admin-btn-ghost"
          onClick={() => addUrl(draft)}
        >
          <Plus className="w-3.5 h-3.5" />
          add url
        </button>
      </div>
      {err && <p className="text-[11px] text-red-400 lowercase">{err}</p>}
      {presets.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[10px] text-zinc-600 lowercase">quick add:</span>
          {presets.map((p) => {
            const exists = items.includes(p.url);
            return (
              <button
                key={p.url}
                type="button"
                disabled={exists}
                onClick={() => addUrl(p.url)}
                className="text-[10px] px-2 py-0.5 border border-zinc-800 text-zinc-400 hover:border-zinc-600 hover:text-zinc-200 disabled:opacity-40 lowercase"
              >
                + {p.label}
              </button>
            );
          })}
        </div>
      )}
      {items.length === 0 ? (
        <div className="border border-dashed border-zinc-800/80 px-3 py-2.5 text-xs text-zinc-600 lowercase">
          {emptyHint}
        </div>
      ) : (
        <div className="divide-y divide-zinc-800/60 border border-zinc-800 bg-[#121212]">
          {items.map((u) => (
            <div key={u} className="flex items-center justify-between gap-3 px-3 py-2 text-xs">
              <span className="text-zinc-200 break-all">{u}</span>
              <button
                type="button"
                onClick={() => onChange(items.filter((x) => x !== u))}
                className="text-zinc-500 hover:text-red-400 p-1 shrink-0"
                title="remove url"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// --- Duration picker (replaces raw seconds input) ---

const DURATION_PRESETS = [
  { label: "server default", seconds: 0 },
  { label: "5 min", seconds: 300 },
  { label: "15 min", seconds: 900 },
  { label: "1 hour", seconds: 3600 },
  { label: "12 hours", seconds: 43200 },
  { label: "24 hours", seconds: 86400 },
  { label: "7 days", seconds: 604800 },
  { label: "30 days", seconds: 2592000 },
  { label: "90 days", seconds: 7776000 },
];

export function formatDurationHuman(seconds: number, defaultLabel: string): string {
  if (!seconds || seconds <= 0) return `server default (${defaultLabel})`;
  if (seconds % 86400 === 0) {
    const d = seconds / 86400;
    return `${d} ${d === 1 ? "day" : "days"} (${seconds}s)`;
  }
  if (seconds % 3600 === 0) {
    const h = seconds / 3600;
    return `${h} ${h === 1 ? "hour" : "hours"} (${seconds}s)`;
  }
  if (seconds % 60 === 0) {
    const m = seconds / 60;
    return `${m} min (${seconds}s)`;
  }
  return `${seconds} seconds`;
}

export function DurationPicker({
  label,
  seconds,
  onChange,
  defaultLabel,
  presets = DURATION_PRESETS,
}: {
  label: string;
  seconds: number;
  onChange: (nextSeconds: number) => void;
  defaultLabel: string;
  presets?: Array<{ label: string; seconds: number }>;
}) {
  return (
    <div className="border border-zinc-800/80 bg-[#121212] p-3.5 space-y-2.5">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs text-zinc-400 lowercase">{label}</span>
        <span className="text-xs font-bold text-zinc-200 lowercase">
          {formatDurationHuman(seconds, defaultLabel)}
        </span>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {presets.map((p) => {
          const active = seconds === p.seconds;
          return (
            <button
              key={p.seconds}
              type="button"
              onClick={() => onChange(p.seconds)}
              className={`px-2 py-1 text-[11px] border lowercase transition-colors ${
                active
                  ? "bg-zinc-300 text-zinc-950 border-zinc-300 font-bold"
                  : "bg-[#1a1a1a] text-zinc-400 border-zinc-800 hover:border-zinc-600 hover:text-zinc-200"
              }`}
            >
              {p.label}
            </button>
          );
        })}
      </div>
      <div className="flex items-center gap-2 pt-1">
        <span className="text-[10px] text-zinc-600 lowercase">custom (seconds, 0 = default):</span>
        <input
          type="number"
          min={0}
          className="input input-sm w-32"
          value={seconds || ""}
          placeholder="0"
          onChange={(e) => onChange(Math.max(0, parseInt(e.target.value, 10) || 0))}
        />
      </div>
    </div>
  );
}

// --- Key-Value metadata editor (replaces raw JSON properties textarea) ---

export interface KeyValueRow {
  key: string;
  value: string;
}

export function recordToRows(rec?: Record<string, string>): KeyValueRow[] {
  if (!rec) return [];
  return Object.entries(rec).map(([key, value]) => ({ key, value }));
}

export function rowsToRecord(rows: KeyValueRow[]): Record<string, string> | undefined {
  const out: Record<string, string> = {};
  for (const r of rows) {
    const k = r.key.trim();
    if (k) out[k] = r.value;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

export function KeyValueEditor({
  rows,
  onChange,
  keyPlaceholder = "key (e.g. team, environment)",
  valuePlaceholder = "value (e.g. platform, production)",
}: {
  rows: KeyValueRow[];
  onChange: (rows: KeyValueRow[]) => void;
  keyPlaceholder?: string;
  valuePlaceholder?: string;
}) {
  const set = (i: number, patch: Partial<KeyValueRow>) =>
    onChange(rows.map((r, j) => (i === j ? { ...r, ...patch } : r)));

  return (
    <div className="space-y-2">
      {rows.map((r, i) => (
        <div key={i} className="flex gap-2 items-center">
          <input
            type="text"
            placeholder={keyPlaceholder}
            className="input w-2/5"
            value={r.key}
            onChange={(e) => set(i, { key: e.target.value })}
          />
          <input
            type="text"
            placeholder={valuePlaceholder}
            className="input flex-1"
            value={r.value}
            onChange={(e) => set(i, { value: e.target.value })}
          />
          <button
            type="button"
            className="admin-btn admin-btn-danger py-1.5 px-2.5"
            onClick={() => onChange(rows.filter((_, j) => j !== i))}
            title="remove row"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      ))}
      <button
        type="button"
        className="admin-btn admin-btn-ghost"
        onClick={() => onChange([...rows, { key: "", value: "" }])}
      >
        <Plus className="w-3.5 h-3.5" />
        add metadata property
      </button>
    </div>
  );
}

// --- Tabs bar ---

export function Tabs<T extends string>({
  tabs,
  active,
  onChange,
}: {
  tabs: Array<{ id: T; label: string; count?: number }>;
  active: T;
  onChange: (id: T) => void;
}) {
  return (
    <div className="flex flex-wrap gap-1 border-b border-zinc-800">
      {tabs.map((t) => {
        const isCurrent = t.id === active;
        return (
          <button
            key={t.id}
            type="button"
            onClick={() => onChange(t.id)}
            className={`px-4 py-2.5 text-xs lowercase transition-colors border-b-2 -mb-px ${
              isCurrent
                ? "border-zinc-200 text-zinc-100 font-bold bg-[#1a1a1a]"
                : "border-transparent text-zinc-500 hover:text-zinc-300"
            }`}
          >
            {t.label}
            {typeof t.count === "number" && (
              <span className="ml-2 px-1.5 py-0.2 bg-zinc-800 text-zinc-400 text-[10px]">
                {t.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
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
  filters,
  action,
}: {
  search?: string;
  onSearch?: (v: string) => void;
  searchPlaceholder?: string;
  filters?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
      <div className="flex flex-wrap items-center gap-2 flex-1">
        {onSearch && (
          <div className="relative max-w-xs w-full">
            <Search className="absolute left-2.5 top-2.5 w-4 h-4 text-zinc-600" />
            <input
              type="text"
              placeholder={searchPlaceholder ?? "search…"}
              className="input pl-8"
              value={search ?? ""}
              onChange={(e) => onSearch(e.target.value)}
            />
          </div>
        )}
        {filters}
      </div>
      {action && <div className="flex items-center gap-2 shrink-0">{action}</div>}
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
  return <span className={`px-2 py-0.5 text-xs lowercase inline-block ${tones[tone]}`}>{children}</span>;
}

// ClaimsEditor edits a Type/Value claim list (user and role claims
// share the wire shape — capitalised keys, matching the Go structs).
export interface ClaimRow {
  Type: string;
  Value: string;
}

const COMMON_CLAIM_TYPES = ["name", "given_name", "family_name", "locale", "picture", "website", "department"];

export function ClaimsEditor({
  rows,
  onChange,
}: {
  rows: ClaimRow[];
  onChange: (rows: ClaimRow[]) => void;
}) {
  const set = (i: number, patch: Partial<ClaimRow>) =>
    onChange(rows.map((r, j) => (i === j ? { ...r, ...patch } : r)));

  function addPreset(claimType: string) {
    const emptyIdx = rows.findIndex((r) => !r.Type.trim() && !r.Value.trim());
    if (emptyIdx >= 0) {
      set(emptyIdx, { Type: claimType });
    } else {
      onChange([...rows, { Type: claimType, Value: "" }]);
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-[10px] text-zinc-500 lowercase">standard oidc claims:</span>
        {COMMON_CLAIM_TYPES.map((ct) => (
          <button
            key={ct}
            type="button"
            onClick={() => addPreset(ct)}
            className="text-[10px] px-2 py-0.5 border border-zinc-800 text-zinc-400 hover:border-zinc-600 hover:text-zinc-200 lowercase"
          >
            + {ct}
          </button>
        ))}
      </div>
      {rows.map((r, i) => (
        <div key={i} className="flex gap-2 items-center">
          <input
            type="text"
            placeholder="claim type (e.g. name, locale)"
            className="input w-2/5"
            value={r.Type}
            onChange={(e) => set(i, { Type: e.target.value })}
          />
          <input
            type="text"
            placeholder="claim value"
            className="input flex-1"
            value={r.Value}
            onChange={(e) => set(i, { Value: e.target.value })}
          />
          <button
            type="button"
            className="admin-btn admin-btn-danger py-1.5 px-2.5"
            onClick={() => onChange(rows.filter((_, j) => j !== i))}
            title="remove claim"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      ))}
      <button
        type="button"
        className="admin-btn admin-btn-ghost"
        onClick={() => onChange([...rows, { Type: "", Value: "" }])}
      >
        <Plus className="w-3.5 h-3.5" />
        add claim row
      </button>
    </div>
  );
}
