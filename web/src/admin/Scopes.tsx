import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Badge, DataTable, ListHeader, Th, useToast } from "./shared";
import { ConfirmDialog, ErrorBanner, Loading, Modal, errorMessage } from "../components/ui";
import { apiDelete, apiGet, apiPost, apiPut } from "../lib/api";
import type { Paged, ScopeView } from "../lib/types";

const STANDARD_SCOPES = new Set(["openid", "profile", "email", "offline_access"]);

interface ScopeFormState {
  name: string;
  display_name: string;
  description: string;
  required: boolean;
  emphasize: boolean;
}

const emptyForm: ScopeFormState = { name: "", display_name: "", description: "", required: false, emphasize: false };

export default function Scopes() {
  const toast = useToast();
  const [items, setItems] = useState<ScopeView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [editing, setEditing] = useState<{ form: ScopeFormState; isEdit: boolean } | null>(null);
  const [deleting, setDeleting] = useState<ScopeView | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      const r = await apiGet<Paged<ScopeView>>("/admin/api/scopes");
      setItems(r.items ?? []);
    } catch (e) {
      setError(errorMessage(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!editing) return;
    setBusy(true);
    setFormError(null);
    try {
      if (editing.isEdit) {
        await apiPut(`/admin/api/scopes/${encodeURIComponent(editing.form.name)}`, editing.form);
        toast("scope updated");
      } else {
        await apiPost("/admin/api/scopes", editing.form);
        toast("scope registered");
      }
      setEditing(null);
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
      await apiDelete(`/admin/api/scopes/${encodeURIComponent(deleting.name)}`);
      toast("scope deleted");
      setDeleting(null);
      await load();
    } catch (e) {
      toast(errorMessage(e), "error");
    } finally {
      setBusy(false);
    }
  }

  const visible = (items ?? []).filter(
    (s) =>
      s.name.toLowerCase().includes(search.toLowerCase()) ||
      (s.display_name ?? "").toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <>
      <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">scopes</h1>
      <ErrorBanner error={error} />
      <ListHeader
        search={search}
        onSearch={setSearch}
        searchPlaceholder="search scopes…"
        action={
          <button type="button" className="admin-btn" onClick={() => setEditing({ form: { ...emptyForm }, isEdit: false })}>
            + new scope
          </button>
        }
      />
      {!items && !error && <Loading text="loading scopes…" />}
      {items && (
        <DataTable
          head={
            <>
              <Th>name</Th>
              <Th>display name</Th>
              <Th>description</Th>
              <Th>required</Th>
              <Th right></Th>
            </>
          }
        >
          {visible.map((s) => (
            <tr key={s.name} className="hover:bg-zinc-800/20">
              <td className="p-4 text-zinc-100">{s.name}</td>
              <td className="p-4 text-zinc-300">{s.display_name}</td>
              <td className="p-4 text-zinc-500 text-xs">{s.description}</td>
              <td className="p-4">
                {s.required ? <Badge tone="amber">required</Badge> : <span className="text-zinc-600 text-xs">—</span>}
                {s.emphasize && <Badge tone="zinc">emphasize</Badge>}
              </td>
              <td className="p-4 text-right whitespace-nowrap space-x-2">
                <button
                  type="button"
                  className="admin-btn admin-btn-ghost"
                  onClick={() =>
                    setEditing({
                      isEdit: true,
                      form: {
                        name: s.name,
                        display_name: s.display_name,
                        description: s.description,
                        required: s.required,
                        emphasize: s.emphasize,
                      },
                    })
                  }
                >
                  edit
                </button>
                {!STANDARD_SCOPES.has(s.name) && (
                  <button type="button" className="admin-btn admin-btn-danger" onClick={() => setDeleting(s)}>
                    delete
                  </button>
                )}
              </td>
            </tr>
          ))}
          {visible.length === 0 && (
            <tr>
              <td colSpan={5} className="p-4 text-sm text-zinc-500 lowercase">
                no scopes match.
              </td>
            </tr>
          )}
        </DataTable>
      )}

      {editing && (
        <Modal title={editing.isEdit ? "edit scope" : "register new scope"} onClose={() => setEditing(null)}>
          <ErrorBanner error={formError} />
          <form className="space-y-4" onSubmit={onSubmit}>
            <div>
              <label className="auth-label">scope key *</label>
              <input
                className="admin-input"
                placeholder="e.g. read_profile"
                required
                readOnly={editing.isEdit}
                value={editing.form.name}
                onChange={(e) => setEditing({ ...editing, form: { ...editing.form, name: e.target.value } })}
              />
            </div>
            <div>
              <label className="auth-label">display name</label>
              <input
                className="admin-input"
                placeholder="e.g. Read Profile Details"
                value={editing.form.display_name}
                onChange={(e) => setEditing({ ...editing, form: { ...editing.form, display_name: e.target.value } })}
              />
            </div>
            <div>
              <label className="auth-label">description</label>
              <input
                className="admin-input"
                placeholder="Allows the client to read profile metadata"
                value={editing.form.description}
                onChange={(e) => setEditing({ ...editing, form: { ...editing.form, description: e.target.value } })}
              />
            </div>
            <div className="space-y-2">
              <label className="flex items-center gap-2 text-sm lowercase text-zinc-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={editing.form.required}
                  onChange={(e) => setEditing({ ...editing, form: { ...editing.form, required: e.target.checked } })}
                />
                required (consent screen cannot skip this)
              </label>
              <label className="flex items-center gap-2 text-sm lowercase text-zinc-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={editing.form.emphasize}
                  onChange={(e) => setEditing({ ...editing, form: { ...editing.form, emphasize: e.target.checked } })}
                />
                emphasize on the consent screen
              </label>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button type="button" className="admin-btn admin-btn-ghost" onClick={() => setEditing(null)}>
                cancel
              </button>
              <button type="submit" className="admin-btn" disabled={busy}>
                {busy ? "saving…" : editing.isEdit ? "save changes" : "create scope"}
              </button>
            </div>
          </form>
        </Modal>
      )}

      {deleting && (
        <ConfirmDialog
          title="delete scope"
          message={`are you sure you want to delete scope "${deleting.name}"?`}
          confirmLabel="delete scope"
          busy={busy}
          onConfirm={() => void onDelete()}
          onClose={() => setDeleting(null)}
        />
      )}
    </>
  );
}
