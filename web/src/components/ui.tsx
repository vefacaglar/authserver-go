import { useEffect, type ReactNode } from "react";
import { ApiError } from "../lib/api";

export function ErrorBanner({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <div className="bg-red-950/20 px-4 py-3 mb-6 border-l-2 border-red-500 text-red-400 text-xs lowercase">
      error: {error}
    </div>
  );
}

export function StatusBanner({ text }: { text: string | null }) {
  if (!text) return null;
  return (
    <div className="bg-emerald-950/20 px-4 py-3 mb-6 border-l-2 border-emerald-500 text-emerald-400 text-xs lowercase">
      {text}
    </div>
  );
}

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error) return e.message;
  return "an unexpected error occurred";
}

export function Field({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div>
      <label className="auth-label">{label}</label>
      {children}
    </div>
  );
}

export function Section({
  title,
  action,
  children,
}: {
  title: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="bg-[#1a1a1a] border border-zinc-800/60 p-6">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-xs text-zinc-500 lowercase tracking-wide">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}

export function DefinitionList({ rows }: { rows: Array<[string, ReactNode]> }) {
  return (
    <dl className="grid grid-cols-[8rem_1fr] gap-y-3 text-sm">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-zinc-500 lowercase">{k}</dt>
          <dd className="text-zinc-300 break-all">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Modal({
  title,
  onClose,
  children,
  wide = false,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/70 p-4" onClick={onClose}>
      <div
        className={`w-full ${wide ? "max-w-2xl" : "max-w-md"} bg-[#1a1a1a] border border-zinc-800 my-8`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-zinc-800/60 px-5 py-3">
          <h3 className="text-sm font-bold text-zinc-300 lowercase tracking-tight">{title}</h3>
          <button type="button" className="auth-link" onClick={onClose} aria-label="close">
            ✕
          </button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

export function ConfirmDialog({
  title,
  message,
  confirmLabel,
  onConfirm,
  onClose,
  busy,
}: {
  title: string;
  message: string;
  confirmLabel: string;
  onConfirm: () => void;
  onClose: () => void;
  busy?: boolean;
}) {
  return (
    <Modal title={title} onClose={onClose}>
      <p className="text-sm text-zinc-400 lowercase mb-6">{message}</p>
      <div className="flex justify-end gap-2">
        <button type="button" className="admin-btn admin-btn-ghost" onClick={onClose} disabled={busy}>
          cancel
        </button>
        <button type="button" className="admin-btn admin-btn-danger" onClick={onConfirm} disabled={busy}>
          {busy ? "working…" : confirmLabel}
        </button>
      </div>
    </Modal>
  );
}

export function EmptyRow({ colSpan, text }: { colSpan: number; text: string }) {
  return (
    <tr>
      <td colSpan={colSpan} className="py-3 text-sm text-zinc-500 lowercase">
        {text}
      </td>
    </tr>
  );
}

export function Loading({ text = "loading…" }: { text?: string }) {
  return <p className="text-sm text-zinc-500 lowercase">{text}</p>;
}
