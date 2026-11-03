import { useEffect, useState, type FormEvent } from "react";
import { useLocation } from "react-router";
import { Badge, DataTable, ListHeader, Pagination, Th, usePagedList, useToast } from "./shared";
import { ConfirmDialog, ErrorBanner, Loading, errorMessage } from "../components/ui";
import { apiDelete, apiGet, apiPost, apiPut } from "../lib/api";
import { linesToList } from "../lib/format";
import type { ClientView, Paged, ScopeView } from "../lib/types";

interface ClientFormState {
  client_id: string;
  display_name: string;
  redirect_uris_text: string;
  post_logout_text: string;
  allowed_scopes: string[];
  token_endpoint_auth_method: string;
  jwks_json: string;
  require_pkce: boolean;
  allow_refresh_tokens: boolean;
  allow_client_credentials: boolean;
  access_lt: string;
  refresh_lt: string;
  refresh_abs_lt: string;
  refresh_expiration: number;
  properties_text: string;
}

function toForm(c: Partial<ClientView>): ClientFormState {
  return {
    client_id: c.client_id ?? "",
    display_name: c.display_name ?? "",
    redirect_uris_text: (c.redirect_uris ?? []).join("\n"),
    post_logout_text: (c.post_logout_redirect_uris ?? []).join("\n"),
    allowed_scopes: c.allowed_scopes ?? ["openid"],
    token_endpoint_auth_method: c.token_endpoint_auth_method || "none",
    jwks_json: c.jwks_json ?? "",
    require_pkce: c.require_pkce !== false,
    allow_refresh_tokens: !!c.allow_refresh_tokens,
    allow_client_credentials: !!c.allow_client_credentials,
    access_lt: c.access_token_lifetime_seconds ? String(c.access_token_lifetime_seconds) : "",
    refresh_lt: c.refresh_token_lifetime_seconds ? String(c.refresh_token_lifetime_seconds) : "",
    refresh_abs_lt: c.refresh_token_absolute_lifetime_seconds ? String(c.refresh_token_absolute_lifetime_seconds) : "",
    refresh_expiration: c.refresh_token_expiration ?? 0,
    properties_text: c.properties ? JSON.stringify(c.properties, null, 2) : "",
  };
}

function fromForm(f: ClientFormState): ClientView {
  let properties: Record<string, string> | undefined;
  const raw = f.properties_text.trim();
  if (raw) {
    try {
      properties = JSON.parse(raw) as Record<string, string>;
    } catch (e) {
      throw new Error("properties: " + (e instanceof Error ? e.message : "invalid json"));
    }
  }
  const num = (s: string) => parseInt(s, 10) || 0;
  const scopes = Array.from(new Set(["openid", ...f.allowed_scopes]));
  return {
    client_id: f.client_id.trim(),
    display_name: f.display_name.trim(),
    redirect_uris: linesToList(f.redirect_uris_text),
    post_logout_redirect_uris: linesToList(f.post_logout_text),
    allowed_scopes: scopes,
    token_endpoint_auth_method: f.token_endpoint_auth_method,
    jwks_json: f.jwks_json.trim() || undefined,
    has_jwks: !!f.jwks_json.trim(),
    require_pkce: f.require_pkce,
    allow_refresh_tokens: f.allow_refresh_tokens,
    allow_client_credentials: f.allow_client_credentials,
    access_token_lifetime_seconds: num(f.access_lt),
    refresh_token_lifetime_seconds: num(f.refresh_lt),
    refresh_token_absolute_lifetime_seconds: num(f.refresh_abs_lt),
    refresh_token_expiration: f.refresh_expiration,
    properties,
  };
}

type View = { kind: "list" } | { kind: "form"; isEdit: boolean; form: ClientFormState };

export default function Clients() {
  const toast = useToast();
  const location = useLocation();
  const list = usePagedList<ClientView>("/admin/api/clients");
  const [search, setSearch] = useState("");
  const [view, setView] = useState<View>({ kind: "list" });
  const [allScopes, setAllScopes] = useState<ScopeView[]>([]);
  const [deleting, setDeleting] = useState<ClientView | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiGet<Paged<ScopeView>>("/admin/api/scopes")
      .then((r) => setAllScopes(r.items ?? []))
      .catch(() =>
        setAllScopes([
          { name: "openid", display_name: "OpenID", description: "", required: true, emphasize: false },
          { name: "profile", display_name: "Profile", description: "", required: false, emphasize: false },
          { name: "email", display_name: "Email", description: "", required: false, emphasize: false },
          { name: "offline_access", display_name: "Offline access", description: "", required: false, emphasize: false },
        ]),
      );
  }, []);

  // Dashboard quick action lands here with { create: true }.
  useEffect(() => {
    if ((location.state as { create?: boolean } | null)?.create) {
      setView({ kind: "form", isEdit: false, form: toForm({ require_pkce: true }) });
    }
  }, [location.state]);

  async function openEdit(id: string) {
    setFormError(null);
    try {
      const c = await apiGet<ClientView>(`/admin/api/clients/${encodeURIComponent(id)}`);
      setView({ kind: "form", isEdit: true, form: toForm(c) });
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
      const body = fromForm(view.form);
      if (view.isEdit) {
        await apiPut(`/admin/api/clients/${encodeURIComponent(body.client_id)}`, body);
        toast("client changes saved");
      } else {
        await apiPost("/admin/api/clients", body);
        toast("client registered");
      }
      setView({ kind: "list" });
      list.reload();
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
      await apiDelete(`/admin/api/clients/${encodeURIComponent(deleting.client_id)}`);
      toast(`client "${deleting.client_id}" deleted`);
      setDeleting(null);
      setView({ kind: "list" });
      list.reload();
    } catch (e) {
      toast(errorMessage(e), "error");
    } finally {
      setBusy(false);
    }
  }

  if (view.kind === "form") {
    const f = view.form;
    const set = (patch: Partial<ClientFormState>) => setView({ ...view, form: { ...f, ...patch } });
    return (
      <>
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">
            {view.isEdit ? "edit client" : "register new client"}
          </h1>
          <button type="button" className="admin-btn admin-btn-ghost" onClick={() => setView({ kind: "list" })}>
            ← back to clients
          </button>
        </div>
        <ErrorBanner error={formError} />
        <form onSubmit={onSubmit} className="bg-[#1a1a1a] border border-zinc-800/60 p-6 md:p-8 space-y-6 max-w-4xl">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div>
                <label className="auth-label">client id *</label>
                <input
                  className="admin-input"
                  required
                  readOnly={view.isEdit}
                  value={f.client_id}
                  onChange={(e) => set({ client_id: e.target.value })}
                />
                <p className="text-[10px] text-zinc-600 lowercase mt-1">unique identifier of the application</p>
              </div>
              <div>
                <label className="auth-label">display name</label>
                <input className="admin-input" value={f.display_name} onChange={(e) => set({ display_name: e.target.value })} />
              </div>
              <div>
                <label className="auth-label">redirect uris</label>
                <textarea
                  className="admin-input h-24 whitespace-pre"
                  placeholder="https://app.example/callback"
                  value={f.redirect_uris_text}
                  onChange={(e) => set({ redirect_uris_text: e.target.value })}
                />
                <p className="text-[10px] text-zinc-600 lowercase mt-1">one absolute url per line. exact match required.</p>
              </div>
              <div>
                <label className="auth-label">post-logout redirect uris</label>
                <textarea
                  className="admin-input h-20 whitespace-pre"
                  placeholder="https://app.example/"
                  value={f.post_logout_text}
                  onChange={(e) => set({ post_logout_text: e.target.value })}
                />
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <label className="auth-label">allowed scopes</label>
                <div className="grid grid-cols-2 gap-2 border border-zinc-800 p-3">
                  {allScopes.map((sc) => {
                    const checked = sc.name === "openid" || f.allowed_scopes.includes(sc.name);
                    return (
                      <label key={sc.name} className="flex items-center gap-2 text-sm lowercase text-zinc-300 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={checked}
                          disabled={sc.name === "openid"}
                          onChange={(e) =>
                            set({
                              allowed_scopes: e.target.checked
                                ? [...f.allowed_scopes, sc.name]
                                : f.allowed_scopes.filter((x) => x !== sc.name),
                            })
                          }
                        />
                        {sc.name}
                      </label>
                    );
                  })}
                </div>
              </div>
              <div>
                <label className="auth-label">client authentication method</label>
                <select
                  className="admin-input"
                  value={f.token_endpoint_auth_method}
                  onChange={(e) => set({ token_endpoint_auth_method: e.target.value })}
                >
                  <option value="none">none (public client — pkce)</option>
                  <option value="private_key_jwt">private_key_jwt (confidential client)</option>
                </select>
              </div>
              {f.token_endpoint_auth_method === "private_key_jwt" && (
                <div>
                  <label className="auth-label">jwks json</label>
                  <textarea
                    className="admin-input h-24 whitespace-pre text-xs"
                    placeholder='{"keys":[{"kty":"RSA","n":"..."}]}'
                    value={f.jwks_json}
                    onChange={(e) => set({ jwks_json: e.target.value })}
                  />
                  <p className="text-[10px] text-zinc-600 lowercase mt-1">
                    the public jwk set used to verify private_key_jwt client assertions
                  </p>
                </div>
              )}
              <div className="space-y-2.5 pt-1">
                <label className="flex items-start gap-3 cursor-pointer">
                  <input type="checkbox" className="mt-1" checked={f.require_pkce} onChange={(e) => set({ require_pkce: e.target.checked })} />
                  <span className="text-sm lowercase">
                    <span className="text-zinc-200 block">require pkce (s256 only)</span>
                    <span className="text-[10px] text-zinc-500">strictly enforce pkce code challenge verification</span>
                  </span>
                </label>
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    className="mt-1"
                    checked={f.allow_refresh_tokens}
                    onChange={(e) => set({ allow_refresh_tokens: e.target.checked })}
                  />
                  <span className="text-sm lowercase">
                    <span className="text-zinc-200 block">allow refresh tokens</span>
                    <span className="text-[10px] text-zinc-500">issues refresh tokens when offline_access is granted</span>
                  </span>
                </label>
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    className="mt-1"
                    checked={f.allow_client_credentials}
                    onChange={(e) => set({ allow_client_credentials: e.target.checked })}
                  />
                  <span className="text-sm lowercase">
                    <span className="text-zinc-200 block">allow client credentials</span>
                    <span className="text-[10px] text-zinc-500">enables the server-to-server grant</span>
                  </span>
                </label>
              </div>
            </div>
          </div>

          <div className="border-t border-zinc-800/60 pt-5">
            <h2 className="text-xs text-zinc-500 lowercase tracking-wide mb-3">lifetimes (seconds, 0 = server default)</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div>
                <label className="auth-label">access token</label>
                <input className="admin-input" type="number" min="0" value={f.access_lt} onChange={(e) => set({ access_lt: e.target.value })} />
              </div>
              <div>
                <label className="auth-label">refresh token</label>
                <input className="admin-input" type="number" min="0" value={f.refresh_lt} onChange={(e) => set({ refresh_lt: e.target.value })} />
              </div>
              <div>
                <label className="auth-label">refresh absolute max</label>
                <input className="admin-input" type="number" min="0" value={f.refresh_abs_lt} onChange={(e) => set({ refresh_abs_lt: e.target.value })} />
              </div>
              <div>
                <label className="auth-label">refresh expiration type</label>
                <select className="admin-input" value={f.refresh_expiration} onChange={(e) => set({ refresh_expiration: parseInt(e.target.value, 10) })}>
                  <option value={0}>sliding</option>
                  <option value={1}>absolute</option>
                </select>
              </div>
            </div>
          </div>

          <div>
            <label className="auth-label">metadata properties (json)</label>
            <textarea
              className="admin-input h-20 whitespace-pre text-xs"
              placeholder='{"team": "security"}'
              value={f.properties_text}
              onChange={(e) => set({ properties_text: e.target.value })}
            />
          </div>

          <div className="flex items-center justify-between pt-4 border-t border-zinc-800/60">
            <div>
              {view.isEdit && (
                <button
                  type="button"
                  className="admin-btn admin-btn-danger"
                  onClick={() => setDeleting({ client_id: f.client_id } as ClientView)}
                >
                  delete client
                </button>
              )}
            </div>
            <div className="flex gap-2">
              <button type="button" className="admin-btn admin-btn-ghost" onClick={() => setView({ kind: "list" })}>
                cancel
              </button>
              <button type="submit" className="admin-btn" disabled={busy}>
                {busy ? "saving…" : view.isEdit ? "save changes" : "register client"}
              </button>
            </div>
          </div>
        </form>
        {deleting && (
          <ConfirmDialog
            title="delete client"
            message={`are you sure you want to delete client "${deleting.client_id}"?`}
            confirmLabel="delete client"
            busy={busy}
            onConfirm={() => void onDelete()}
            onClose={() => setDeleting(null)}
          />
        )}
      </>
    );
  }

  const visible = list.items.filter(
    (c) =>
      c.client_id.toLowerCase().includes(search.toLowerCase()) ||
      (c.display_name ?? "").toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <>
      <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">clients</h1>
      <ErrorBanner error={list.error} />
      <ListHeader
        search={search}
        onSearch={setSearch}
        searchPlaceholder="search clients…"
        action={
          <button type="button" className="admin-btn" onClick={() => setView({ kind: "form", isEdit: false, form: toForm({ require_pkce: true }) })}>
            + new client
          </button>
        }
      />
      {list.loading && <Loading text="loading clients…" />}
      {!list.loading && (
        <>
          <DataTable
            head={
              <>
                <Th>client_id</Th>
                <Th>name</Th>
                <Th>auth</Th>
                <Th>scopes</Th>
                <Th>pkce</Th>
                <Th>jwks</Th>
                <Th right></Th>
              </>
            }
          >
            {visible.map((c) => (
              <tr key={c.client_id} className="hover:bg-zinc-800/20">
                <td className="p-4 text-zinc-100">{c.client_id}</td>
                <td className="p-4 text-zinc-300">{c.display_name}</td>
                <td className="p-4">
                  <Badge tone={c.token_endpoint_auth_method === "private_key_jwt" ? "amber" : "zinc"}>
                    {c.token_endpoint_auth_method}
                  </Badge>
                </td>
                <td className="p-4 text-zinc-500 text-xs max-w-xs truncate" title={(c.allowed_scopes ?? []).join(", ")}>
                  {(c.allowed_scopes ?? []).join(", ")}
                </td>
                <td className="p-4 text-zinc-300 text-xs">{c.require_pkce ? "yes" : "—"}</td>
                <td className="p-4">{c.has_jwks ? <Badge tone="zinc">set</Badge> : <span className="text-zinc-600 text-xs">none</span>}</td>
                <td className="p-4 text-right whitespace-nowrap space-x-2">
                  <button type="button" className="admin-btn admin-btn-ghost" onClick={() => void openEdit(c.client_id)}>
                    edit
                  </button>
                  <button type="button" className="admin-btn admin-btn-danger" onClick={() => setDeleting(c)}>
                    delete
                  </button>
                </td>
              </tr>
            ))}
            {visible.length === 0 && (
              <tr>
                <td colSpan={7} className="p-4 text-sm text-zinc-500 lowercase">
                  no clients match.
                </td>
              </tr>
            )}
          </DataTable>
          <Pagination page={list.page} pageSize={list.pageSize} total={list.total} onPage={(p) => void list.load(p)} />
        </>
      )}
      {deleting && (
        <ConfirmDialog
          title="delete client"
          message={`are you sure you want to delete client "${deleting.client_id}"?`}
          confirmLabel="delete client"
          busy={busy}
          onConfirm={() => void onDelete()}
          onClose={() => setDeleting(null)}
        />
      )}
    </>
  );
}
