import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Plus } from "lucide-react";
import {
  Badge,
  DataTable,
  KeyValueEditor,
  ListHeader,
  Th,
  ToggleCard,
  recordToRows,
  rowsToRecord,
  useToast,
  type KeyValueRow,
} from "./shared";
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
  property_rows: KeyValueRow[];
}

const emptyForm: ScopeFormState = {
  name: "",
  display_name: "",
  description: "",
  required: false,
  emphasize: false,
  property_rows: [],
};

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
    const payload: ScopeView = {
      name: editing.form.name.trim(),
      display_name: editing.form.display_name.trim(),
      description: editing.form.description.trim(),
      required: editing.form.required,
      emphasize: editing.form.emphasize,
      properties: rowsToRecord(editing.form.property_rows),
    };
    try {
      if (editing.isEdit) {
        await apiPut(`/admin/api/scopes/${encodeURIComponent(payload.name)}`, payload);
        toast("scope updated");
      } else {
        await apiPost("/admin/api/scopes", payload);
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
      (s.display_name ?? "").toLowerCase().includes(search.toLowerCase()) ||
      (s.description ?? "").toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <>
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-[20px] font-semibold text-[var(--text-heading)] lowercase m-0">scopes</h1>
          <p className="text-[13px] text-[var(--muted)] lowercase mt-1 m-0">
            oauth2 permission scopes and openid connect claim bundles
          </p>
        </div>
        <button
          type="button"
          className="admin-btn"
          onClick={() => {
            setFormError(null);
            setEditing({ form: { ...emptyForm }, isEdit: false });
          }}
        >
          <Plus className="w-3.5 h-3.5" />
          new scope
        </button>
      </div>
      <ErrorBanner error={error} />
      <ListHeader search={search} onSearch={setSearch} searchPlaceholder="search scopes…" />
      {!items && !error && <Loading text="loading scopes…" />}
      {items && (
        <DataTable
          head={
            <>
              <Th>scope key</Th>
              <Th>display name</Th>
              <Th>description</Th>
              <Th>flags</Th>
              <Th right>actions</Th>
            </>
          }
        >
          {visible.map((s) => (
            <tr key={s.name} className="hover:bg-[var(--border)]/35 transition-colors">
              <td className="p-4 text-[var(--text-heading)] font-semibold">
                {s.name}
                {STANDARD_SCOPES.has(s.name) && (
                  <span className="ml-2 text-[11px] font-normal text-[var(--muted)] border border-[var(--border)] px-1.5 py-0.5">
                    standard
                  </span>
                )}
              </td>
              <td className="p-4 text-[var(--text)]">{s.display_name || "—"}</td>
              <td className="p-4 text-[var(--muted)] text-xs">{s.description || "—"}</td>
              <td className="p-4 space-x-1.5">
                {s.required && <Badge tone="amber">required</Badge>}
                {s.emphasize && <Badge tone="zinc">emphasize</Badge>}
                {!s.required && !s.emphasize && <span className="text-[var(--muted)] text-xs">—</span>}
              </td>
              <td className="p-4 text-right whitespace-nowrap space-x-2">
                <button
                  type="button"
                  className="admin-btn admin-btn-ghost"
                  onClick={() => {
                    setFormError(null);
                    setEditing({
                      isEdit: true,
                      form: {
                        name: s.name,
                        display_name: s.display_name,
                        description: s.description,
                        required: s.required,
                        emphasize: s.emphasize,
                        property_rows: recordToRows(s.properties),
                      },
                    });
                  }}
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
              <td colSpan={5} className="p-6 text-sm text-[var(--muted)] lowercase text-center">
                no scopes match.
              </td>
            </tr>
          )}
        </DataTable>
      )}

      {editing && (
        <Modal wide title={editing.isEdit ? `edit scope — ${editing.form.name}` : "register new scope"} onClose={() => setEditing(null)}>
          <ErrorBanner error={formError} />
          <form className="space-y-4" onSubmit={onSubmit}>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="auth-label">scope key (token identifier) *</label>
                <input
                  className="input"
                  placeholder="e.g. billing:read"
                  required
                  readOnly={editing.isEdit}
                  value={editing.form.name}
                  onChange={(e) => setEditing({ ...editing, form: { ...editing.form, name: e.target.value } })}
                />
              </div>
              <div>
                <label className="auth-label">display name</label>
                <input
                  className="input"
                  placeholder="e.g. Read Billing Data"
                  value={editing.form.display_name}
                  onChange={(e) => setEditing({ ...editing, form: { ...editing.form, display_name: e.target.value } })}
                />
              </div>
            </div>
            <div>
              <label className="auth-label">description</label>
              <input
                className="input"
                placeholder="shown on consent screens to explain what access this scope grants"
                value={editing.form.description}
                onChange={(e) => setEditing({ ...editing, form: { ...editing.form, description: e.target.value } })}
              />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <ToggleCard
                checked={editing.form.required}
                onChange={(required) => setEditing({ ...editing, form: { ...editing.form, required } })}
                title="required scope"
                description="users cannot uncheck this scope on the consent screen."
              />
              <ToggleCard
                checked={editing.form.emphasize}
                onChange={(emphasize) => setEditing({ ...editing, form: { ...editing.form, emphasize } })}
                title="emphasize on consent"
                description="highlights this scope visually for high-privilege access."
              />
            </div>
            <div>
              <label className="auth-label">metadata properties</label>
              <KeyValueEditor
                rows={editing.form.property_rows}
                onChange={(property_rows) => setEditing({ ...editing, form: { ...editing.form, property_rows } })}
              />
            </div>
            <div className="flex justify-end gap-2 pt-3 border-t border-[var(--border)]">
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
