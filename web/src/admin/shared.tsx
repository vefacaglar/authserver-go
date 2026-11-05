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
                ? "border border-[var(--accent)] bg-[var(--bg)] text-[var(--accent)] px-4 py-3 text-xs lowercase"
                : "border border-[var(--text-heading)] bg-[var(--text-heading)] text-[var(--bg)] px-4 py-3 text-xs font-bold lowercase"
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
      {copied ? <Check className="w-3 h-3 text-[var(--success)]" /> : <Copy className="w-3 h-3" />}
      {copied ? "copied" : label}
    </button>
  );
}

// --- custom square toggle switch & card (styled after vefacaglar.com jobs.module.css) ---

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
      className={`inline-flex items-center w-[30px] h-[16px] p-[2px] border transition-colors shrink-0 ${
        disabled ? "opacity-50" : ""
      } ${
        checked
          ? "bg-[var(--success)]/20 border-[var(--success)] justify-end"
          : "bg-transparent border-[var(--muted)] justify-start"
      }`}
    >
      <span className={`w-[10px] h-[10px] ${checked ? "bg-[var(--success)]" : "bg-[var(--muted)]"}`} />
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
      className={`w-full text-left p-4 border transition-colors flex items-start justify-between gap-4 ${
        disabled ? "cursor-not-allowed opacity-60" : "cursor-pointer"
      } ${
        checked
          ? "bg-[var(--bg)] border-[var(--accent)]"
          : "bg-[var(--bg)] border-[var(--border)] hover:border-[var(--muted)]"
      }`}
    >
      <div className="min-w-0 space-y-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`text-[13px] font-semibold lowercase ${checked ? "text-[var(--text-heading)]" : "text-[var(--text)]"}`}>
            {title}
          </span>
          {badge}
        </div>
        {description && <p className="text-[12px] text-[var(--muted)] lowercase leading-relaxed m-0">{description}</p>}
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
      {err && <p className="text-[12px] text-[var(--accent)] lowercase m-0">{err}</p>}
      {presets.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] text-[var(--muted)] lowercase">quick add:</span>
          {presets.map((p) => {
            const exists = items.includes(p.url);
            return (
              <button
                key={p.url}
                type="button"
                disabled={exists}
                onClick={() => addUrl(p.url)}
                className="chip text-[11px] py-0.5 px-2"
              >
                + {p.label}
              </button>
            );
          })}
        </div>
      )}
      {items.length === 0 ? (
        <div className="border border-dashed border-[var(--border)] px-3 py-2.5 text-xs text-[var(--muted)] lowercase">
          {emptyHint}
        </div>
      ) : (
        <div className="divide-y divide-[var(--border)] border border-[var(--border)] bg-[var(--bg)]">
          {items.map((u) => (
            <div key={u} className="flex items-center justify-between gap-3 px-3 py-2 text-xs">
              <span className="text-[var(--text-heading)] break-all">{u}</span>
              <button
                type="button"
                onClick={() => onChange(items.filter((x) => x !== u))}
                className="text-[var(--muted)] hover:text-[var(--accent)] p-1 shrink-0 cursor-pointer bg-transparent border-0"
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
    <div className="border border-[var(--border)] bg-[var(--bg)] p-4 space-y-3">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs text-[var(--muted)] lowercase">{label}</span>
        <span className="text-xs font-semibold text-[var(--text-heading)] lowercase">
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
              className={`chip ${active ? "chip-active" : ""}`}
            >
              {p.label}
            </button>
          );
        })}
      </div>
      <div className="flex items-center gap-2 pt-1">
        <span className="text-[11px] text-[var(--muted)] lowercase">custom (seconds, 0 = default):</span>
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

// --- Tabs bar (styled after vefacaglar.com dashboard.module.css) ---

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
    <div className="flex flex-wrap gap-6 border-b border-[var(--border)] pb-3">
      {tabs.map((t) => {
        const isCurrent = t.id === active;
        return (
          <button
            key={t.id}
            type="button"
            onClick={() => onChange(t.id)}
            className={`text-[14px] lowercase transition-colors relative cursor-pointer bg-transparent border-0 p-0 ${
              isCurrent
                ? "text-[var(--text-heading)] font-semibold after:content-[''] after:absolute after:-bottom-[13px] after:left-0 after:right-0 after:h-[2px] after:bg-[var(--accent)]"
                : "text-[var(--muted)] font-medium hover:text-[var(--text)]"
            }`}
          >
            {t.label}
            {typeof t.count === "number" && (
              <span
                className={`ml-2 px-1.5 py-0.5 border border-[var(--border)] text-[11px] tabular-nums ${
                  isCurrent ? "text-[var(--accent)]" : "text-[var(--muted)]"
                }`}
              >
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
    <div className="flex items-center justify-between mt-5 text-[13px] lowercase">
      <span className="text-[var(--muted)]">
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
            <Search className="absolute left-3 top-2.5 w-4 h-4 text-[var(--muted)]" />
            <input
              type="text"
              placeholder={searchPlaceholder ?? "search…"}
              className="input pl-9"
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
    <div className="bg-[var(--bg)] border border-[var(--border)] mt-4">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-[var(--border)] text-[var(--muted)] text-[12px] lowercase">{head}</tr>
          </thead>
          <tbody className="divide-y divide-[var(--border)] text-[13px]">{children}</tbody>
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
    zinc: "bg-[var(--muted)]/15 text-[var(--muted)]",
    emerald: "bg-[var(--success)]/15 text-[var(--success)]",
    red: "bg-[var(--accent)]/15 text-[var(--accent)]",
    amber: "bg-[var(--warning)]/15 text-[var(--warning)]",
  };
  return <span className={`px-2 py-0.5 text-[12px] font-medium lowercase inline-block ${tones[tone]}`}>{children}</span>;
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
        <span className="text-[11px] text-[var(--muted)] lowercase">standard oidc claims:</span>
        {COMMON_CLAIM_TYPES.map((ct) => (
          <button
            key={ct}
            type="button"
            onClick={() => addPreset(ct)}
            className="chip text-[11px] py-0.5 px-2"
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
