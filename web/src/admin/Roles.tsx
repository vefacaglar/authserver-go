import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Plus } from "lucide-react";
import { ClaimsEditor, DataTable, ListHeader, Th, useToast, type ClaimRow } from "./shared";
import { ConfirmDialog, ErrorBanner, Loading, Modal, errorMessage } from "../components/ui";
import { apiDelete, apiGet, apiPost, apiPut } from "../lib/api";
import type { Paged, RoleView } from "../lib/types";

type View =
  | { kind: "list" }
  | { kind: "form"; role: RoleView | null }
  | { kind: "claims"; role: RoleView; rows: ClaimRow[] };

function slugifyRoleId(name: string): string {
  return name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
}

export default function Roles() {
  const toast = useToast();
  const [items, setItems] = useState<RoleView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [view, setView] = useState<View>({ kind: "list" });
  const [deleting, setDeleting] = useState<RoleView | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [formId, setFormId] = useState("");
  const [formName, setFormName] = useState("");
  const [idTouched, setIdTouched] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      const r = await apiGet<Paged<RoleView>>("/admin/api/roles");
      setItems(r.items ?? []);
    } catch (e) {
      setError(errorMessage(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  function openForm(role: RoleView | null) {
    setFormId(role?.id ?? "");
    setFormName(role?.name ?? "");
    setIdTouched(!!role);
    setFormError(null);
    setView({ kind: "form", role });
  }

  async function openClaims(role: RoleView) {
    setFormError(null);
    try {
      const r = await apiGet<{ claims: ClaimRow[] }>(`/admin/api/roles/${encodeURIComponent(role.id)}/claims`);
      setView({ kind: "claims", role, rows: r.claims?.length ? r.claims : [{ Type: "", Value: "" }] });
    } catch (e) {
      toast(errorMessage(e), "error");
    }
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (view.kind !== "form") return;
    setBusy(true);
    setFormError(null);
    try {
      if (view.role) {
        await apiPut(`/admin/api/roles/${encodeURIComponent(view.role.id)}`, { id: view.role.id, name: formName.trim() });
        toast("role updated");
      } else {
        await apiPost("/admin/api/roles", { id: formId.trim(), name: formName.trim() });
        toast("role created");
      }
      setView({ kind: "list" });
      await load();
    } catch (err) {
      setFormError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function onDelete() {
    if (!deleting) return;
    setBusy(true);
    try {
      await apiDelete(`/admin/api/roles/${encodeURIComponent(deleting.id)}`);
      toast("role deleted");
      setDeleting(null);
      await load();
    } catch (e) {
      toast(errorMessage(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function onSaveClaims() {
    if (view.kind !== "claims") return;
    const rows = view.rows.filter((r) => r.Type.trim() !== "" || r.Value.trim() !== "");
    if (rows.some((r) => r.Type.trim() === "" || r.Value.trim() === "")) {
      setFormError("both claim name and value are required.");
      return;
    }
    setBusy(true);
    setFormError(null);
    try {
      await apiPut(`/admin/api/roles/${encodeURIComponent(view.role.id)}/claims`, { claims: rows });
      toast("role claims updated");
      setView({ kind: "list" });
    } catch (e) {
      setFormError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  if (view.kind === "claims") {
    return (
      <div className="space-y-6 max-w-2xl">
        <div className="flex items-center justify-between pb-4 border-b border-[var(--border)]">
          <div>
            <div className="flex items-center gap-3">
              <button
                type="button"
                className="text-xs text-[var(--muted)] hover:text-[var(--accent)] lowercase cursor-pointer bg-transparent border-0 p-0 transition-colors"
                onClick={() => setView({ kind: "list" })}
              >
                ← roles
              </button>
              <span className="text-[var(--border)]">|</span>
              <h1 className="text-[20px] font-semibold text-[var(--text-heading)] lowercase m-0">
                role claims — {view.role.name}
              </h1>
            </div>
            <p className="text-[13px] text-[var(--muted)] lowercase mt-1 m-0">
              claims attached to this role are inherited by every user assigned to it.
            </p>
          </div>
          <div className="flex gap-2">
            <button type="button" className="admin-btn admin-btn-ghost" onClick={() => setView({ kind: "list" })}>
              cancel
            </button>
            <button type="button" className="admin-btn" disabled={busy} onClick={() => void onSaveClaims()}>
              {busy ? "saving…" : "save claims"}
            </button>
          </div>
        </div>
        <section className="bg-[var(--bg)] border border-[var(--border)] p-6 space-y-5">
          <ErrorBanner error={formError} />
          <ClaimsEditor rows={view.rows} onChange={(rows) => setView({ ...view, rows })} />
          <div className="flex justify-end gap-2 pt-3 border-t border-[var(--border)]">
            <button type="button" className="admin-btn admin-btn-ghost" onClick={() => setView({ kind: "list" })}>
              cancel
            </button>
            <button type="button" className="admin-btn" disabled={busy} onClick={() => void onSaveClaims()}>
              {busy ? "saving…" : "save claims"}
            </button>
          </div>
        </section>
      </div>
    );
  }

  const visible = (items ?? []).filter(
    (r) => r.name.toLowerCase().includes(search.toLowerCase()) || r.id.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <>
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-[20px] font-semibold text-[var(--text-heading)] lowercase m-0">roles</h1>
          <p className="text-[13px] text-[var(--muted)] lowercase mt-1 m-0">
            role-based access groups and inherited claim sets
          </p>
        </div>
        <button type="button" className="admin-btn" onClick={() => openForm(null)}>
          <Plus className="w-3.5 h-3.5" />
          new role
        </button>
      </div>
      <ErrorBanner error={error} />
      <ListHeader search={search} onSearch={setSearch} searchPlaceholder="search roles…" />
      {!items && !error && <Loading text="loading roles…" />}
      {items && (
        <DataTable
          head={
            <>
              <Th>role name</Th>
              <Th>role id</Th>
              <Th right>actions</Th>
            </>
          }
        >
          {visible.map((r) => (
            <tr key={r.id} className="hover:bg-[var(--border)]/35 transition-colors">
              <td className="p-4 text-[var(--text-heading)] font-semibold">{r.name}</td>
              <td className="p-4 text-[var(--muted)] text-xs break-all">{r.id}</td>
              <td className="p-4 text-right whitespace-nowrap space-x-2">
                <button type="button" className="admin-btn admin-btn-ghost" onClick={() => void openClaims(r)}>
                  claims
                </button>
                <button type="button" className="admin-btn admin-btn-ghost" onClick={() => openForm(r)}>
                  rename
                </button>
                <button type="button" className="admin-btn admin-btn-danger" onClick={() => setDeleting(r)}>
                  delete
                </button>
              </td>
            </tr>
          ))}
          {visible.length === 0 && (
            <tr>
              <td colSpan={3} className="p-6 text-sm text-[var(--muted)] lowercase text-center">
                no roles match.
              </td>
            </tr>
          )}
        </DataTable>
      )}

      {view.kind === "form" && (
        <Modal title={view.role ? "edit role" : "create new role"} onClose={() => setView({ kind: "list" })}>
          <ErrorBanner error={formError} />
          <form className="space-y-4" onSubmit={onSubmit}>
            <div>
              <label className="auth-label">role name *</label>
              <input
                className="input"
                placeholder="e.g. admin, editor, billing-manager"
                required
                value={formName}
                onChange={(e) => {
                  const name = e.target.value;
                  setFormName(name);
                  if (!view.role && !idTouched) {
                    setFormId(slugifyRoleId(name));
                  }
                }}
              />
            </div>
            <div>
              <label className="auth-label">role id (auto-filled if empty)</label>
              <input
                className="input"
                readOnly={!!view.role}
                placeholder="auto-generated from role name"
                value={formId}
                onChange={(e) => {
                  setIdTouched(true);
                  setFormId(e.target.value);
                }}
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button type="button" className="admin-btn admin-btn-ghost" onClick={() => setView({ kind: "list" })}>
                cancel
              </button>
              <button type="submit" className="admin-btn" disabled={busy}>
                {busy ? "saving…" : view.role ? "save role" : "create role"}
              </button>
            </div>
          </form>
        </Modal>
      )}

      {deleting && (
        <ConfirmDialog
          title="delete role"
          message={`are you sure you want to delete role "${deleting.name}"?`}
          confirmLabel="delete role"
          busy={busy}
          onConfirm={() => void onDelete()}
          onClose={() => setDeleting(null)}
        />
      )}
    </>
  );
}
