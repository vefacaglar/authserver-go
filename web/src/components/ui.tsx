import { useEffect, type ReactNode } from "react";
import { ApiError } from "../lib/api";

export function ErrorBanner({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <div className="errorMsg mb-6 lowercase">
      error: {error}
    </div>
  );
}

export function StatusBanner({ text }: { text: string | null }) {
  if (!text) return null;
  return (
    <div className="successMsg mb-6 lowercase">
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
    <section className="bg-[var(--bg)] border border-[var(--border)] p-6">
      <div className="mb-5 flex items-center justify-between gap-4 pb-3 border-b border-[var(--border)]">
        <h2 className="text-[15px] font-semibold text-[var(--text-heading)] lowercase m-0">{title}</h2>
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
          <dt className="text-[var(--muted)] lowercase">{k}</dt>
          <dd className="text-[var(--text-heading)] break-all">{v}</dd>
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
    <div
      className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto bg-black/60 backdrop-blur-[4px] p-4"
      onClick={onClose}
    >
      <div
        className={`w-full ${wide ? "max-w-2xl" : "max-w-[440px]"} bg-[var(--bg)] border border-[var(--border)] p-6 shadow-[0_20px_40px_rgba(0,0,0,0.5)] my-8`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-dashed border-[var(--border)] pb-3 mb-5">
          <h3 className="text-[13px] font-semibold text-[var(--text-heading)] uppercase tracking-[0.05em] m-0">
            {title}
          </h3>
          <button
            type="button"
            className="bg-transparent border-0 text-[var(--muted)] hover:text-[var(--text-heading)] text-lg leading-none cursor-pointer p-0 transition-colors"
            onClick={onClose}
            aria-label="close"
          >
            ✕
          </button>
        </div>
        <div>{children}</div>
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
      <p className="text-[14px] text-[var(--text)] lowercase mb-6 leading-relaxed">{message}</p>
      <div className="flex justify-end gap-3">
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
      <td colSpan={colSpan} className="py-4 text-sm text-[var(--muted)] lowercase">
        {text}
      </td>
    </tr>
  );
}

export function Loading({ text = "loading…" }: { text?: string }) {
  return <p className="text-sm text-[var(--muted)] lowercase">{text}</p>;
}
