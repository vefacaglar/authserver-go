import { useCallback, useEffect, useState, type FormEvent } from "react";
import { ClaimsEditor, DataTable, ListHeader, Th, useToast, type ClaimRow } from "./shared";
import { ConfirmDialog, ErrorBanner, Loading, Modal, errorMessage } from "../components/ui";
import { apiDelete, apiGet, apiPost, apiPut } from "../lib/api";
import type { Paged, RoleView } from "../lib/types";

type View =
  | { kind: "list" }
  | { kind: "form"; role: RoleView | null }
  | { kind: "claims"; role: RoleView; rows: ClaimRow[] };

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
        await apiPut(`/admin/api/roles/${encodeURIComponent(view.role.id)}`, { id: view.role.id, name: formName });
        toast("role updated");
      } else {
        await apiPost("/admin/api/roles", { id: formId, name: formName });
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
      <>
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">
            role claims — <span className="text-zinc-100">{view.role.name}</span>
          </h1>
          <button type="button" className="admin-btn admin-btn-ghost" onClick={() => setView({ kind: "list" })}>
            ← back to roles
          </button>
        </div>
        <section className="bg-[#1a1a1a] border border-zinc-800/60 p-6 max-w-2xl space-y-5">
          <ErrorBanner error={formError} />
          <ClaimsEditor rows={view.rows} onChange={(rows) => setView({ ...view, rows })} />
          <div className="flex justify-end gap-2 pt-2 border-t border-zinc-800/60">
            <button type="button" className="admin-btn admin-btn-ghost" onClick={() => setView({ kind: "list" })}>
              cancel
            </button>
            <button type="button" className="admin-btn" disabled={busy} onClick={() => void onSaveClaims()}>
              {busy ? "saving…" : "save claims"}
            </button>
          </div>
        </section>
      </>
    );
  }

  const visible = (items ?? []).filter(
    (r) => r.name.toLowerCase().includes(search.toLowerCase()) || r.id.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <>
      <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">roles</h1>
      <ErrorBanner error={error} />
      <ListHeader
        search={search}
        onSearch={setSearch}
        searchPlaceholder="search roles…"
        action={
          <button type="button" className="admin-btn" onClick={() => openForm(null)}>
            + new role
          </button>
        }
      />
      {!items && !error && <Loading text="loading roles…" />}
      {items && (
        <DataTable
          head={
            <>
              <Th>role id</Th>
              <Th>name</Th>
              <Th right></Th>
            </>
          }
        >
          {visible.map((r) => (
            <tr key={r.id} className="hover:bg-zinc-800/20">
              <td className="p-4 text-zinc-300 break-all">{r.id}</td>
              <td className="p-4 text-zinc-100">{r.name}</td>
              <td className="p-4 text-right whitespace-nowrap space-x-2">
                <button type="button" className="admin-btn admin-btn-ghost" onClick={() => openForm(r)}>
                  edit
                </button>
                <button type="button" className="admin-btn admin-btn-ghost" onClick={() => void openClaims(r)}>
                  claims
                </button>
                <button type="button" className="admin-btn admin-btn-danger" onClick={() => setDeleting(r)}>
                  delete
                </button>
              </td>
            </tr>
          ))}
          {visible.length === 0 && (
            <tr>
              <td colSpan={3} className="p-4 text-sm text-zinc-500 lowercase">
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
              <label className="auth-label">role id *</label>
              <input
                className="admin-input"
                required
                readOnly={!!view.role}
                value={formId}
                onChange={(e) => setFormId(e.target.value)}
              />
            </div>
            <div>
              <label className="auth-label">name *</label>
              <input className="admin-input" required value={formName} onChange={(e) => setFormName(e.target.value)} />
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
