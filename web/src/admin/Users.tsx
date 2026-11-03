import { useEffect, useState, type FormEvent } from "react";
import { useLocation } from "react-router";
import { Badge, ClaimsEditor, DataTable, ListHeader, Pagination, Th, usePagedList, useToast, type ClaimRow } from "./shared";
import { ConfirmDialog, ErrorBanner, Loading, errorMessage } from "../components/ui";
import { apiDelete, apiGet, apiPost, apiPut } from "../lib/api";
import { formatUTC } from "../lib/format";
import type { Paged, RoleView, UserView } from "../lib/types";

interface UserLogin {
  LoginProvider: string;
  ProviderKey: string;
  ProviderName: string;
  UserID: string;
}

type View =
  | { kind: "list" }
  | { kind: "create" }
  | { kind: "edit"; user: UserView; logins: UserLogin[] }
  | { kind: "claims"; user: UserView; rows: ClaimRow[] }
  | { kind: "roles"; user: UserView; all: RoleView[]; active: string[] };

export default function Users() {
  const toast = useToast();
  const location = useLocation();
  const list = usePagedList<UserView>("/admin/api/users");
  const [search, setSearch] = useState("");
  const [view, setView] = useState<View>({ kind: "list" });
  const [deleting, setDeleting] = useState<UserView | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // create/edit form fields
  const [fId, setFId] = useState("");
  const [fUsername, setFUsername] = useState("");
  const [fEmail, setFEmail] = useState("");
  const [fPassword, setFPassword] = useState("");
  const [fEmailConfirmed, setFEmailConfirmed] = useState(false);
  const [fTwoFactor, setFTwoFactor] = useState(false);
  const [fLockoutEnabled, setFLockoutEnabled] = useState(false);
  const [newPassword, setNewPassword] = useState("");

  useEffect(() => {
    if ((location.state as { create?: boolean } | null)?.create) {
      openCreate();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.state]);

  function openCreate() {
    setFId("");
    setFUsername("");
    setFEmail("");
    setFPassword("");
    setFormError(null);
    setView({ kind: "create" });
  }

  async function openEdit(id: string) {
    setFormError(null);
    try {
      const [user, loginsRes] = await Promise.all([
        apiGet<UserView>(`/admin/api/users/${encodeURIComponent(id)}`),
        apiGet<{ logins: UserLogin[] }>(`/admin/api/users/${encodeURIComponent(id)}/logins`).catch(() => ({ logins: [] })),
      ]);
      setFId(user.id);
      setFUsername(user.username);
      setFEmail(user.email);
      setFEmailConfirmed(user.email_confirmed);
      setFTwoFactor(user.two_factor_enabled);
      setFLockoutEnabled(user.lockout_enabled);
      setNewPassword("");
      setView({ kind: "edit", user, logins: loginsRes.logins ?? [] });
    } catch (e) {
      toast(errorMessage(e), "error");
    }
  }

  async function openClaims(user: UserView) {
    setFormError(null);
    try {
      const r = await apiGet<{ claims: ClaimRow[] }>(`/admin/api/users/${encodeURIComponent(user.id)}/claims`);
      setView({ kind: "claims", user, rows: r.claims?.length ? r.claims : [{ Type: "", Value: "" }] });
    } catch (e) {
      toast(errorMessage(e), "error");
    }
  }

  async function openRoles(user: UserView) {
    setFormError(null);
    try {
      const [rolesRes, userRolesRes] = await Promise.all([
        apiGet<Paged<RoleView>>("/admin/api/roles"),
        apiGet<{ roles: string[] }>(`/admin/api/users/${encodeURIComponent(user.id)}/roles`),
      ]);
      setView({ kind: "roles", user, all: rolesRes.items ?? [], active: userRolesRes.roles ?? [] });
    } catch (e) {
      toast(errorMessage(e), "error");
    }
  }

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setFormError(null);
    try {
      await apiPost("/admin/api/users", { id: fId.trim(), username: fUsername.trim(), email: fEmail.trim(), password: fPassword });
      toast("user created");
      setView({ kind: "list" });
      list.reload();
    } catch (err) {
      setFormError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function onSaveEdit(e: FormEvent) {
    e.preventDefault();
    if (view.kind !== "edit") return;
    setBusy(true);
    setFormError(null);
    try {
      await apiPut(`/admin/api/users/${encodeURIComponent(view.user.id)}`, {
        username: fUsername.trim(),
        email: fEmail.trim(),
        email_confirmed: fEmailConfirmed,
        two_factor_enabled: fTwoFactor,
        lockout_enabled: fLockoutEnabled,
        lockout_end: view.user.lockout_end ?? null,
        access_failed_count: view.user.access_failed_count,
      });
      if (newPassword) {
        await apiPost(`/admin/api/users/${encodeURIComponent(view.user.id)}/password`, { password: newPassword });
      }
      toast("user profile updated");
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
      await apiDelete(`/admin/api/users/${encodeURIComponent(deleting.id)}`);
      toast(`user "${deleting.username}" deleted`);
      setDeleting(null);
      setView({ kind: "list" });
      list.reload();
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
      await apiPut(`/admin/api/users/${encodeURIComponent(view.user.id)}/claims`, { claims: rows });
      toast("user claims updated");
      setView({ kind: "list" });
    } catch (e) {
      setFormError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  async function onSaveRoles() {
    if (view.kind !== "roles") return;
    setBusy(true);
    setFormError(null);
    try {
      await apiPut(`/admin/api/users/${encodeURIComponent(view.user.id)}/roles`, { roles: view.active });
      toast("user roles updated");
      setView({ kind: "list" });
    } catch (e) {
      setFormError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  async function onRemoveLogin(user: UserView, login: UserLogin) {
    try {
      await apiDelete(
        `/admin/api/users/${encodeURIComponent(user.id)}/logins/${encodeURIComponent(login.LoginProvider)}/${encodeURIComponent(login.ProviderKey)}`,
      );
      toast("external login removed");
      await openEdit(user.id);
    } catch (e) {
      toast(errorMessage(e), "error");
    }
  }

  const backButton = (
    <button type="button" className="admin-btn admin-btn-ghost" onClick={() => setView({ kind: "list" })}>
      ← back to users
    </button>
  );

  if (view.kind === "create" || view.kind === "edit") {
    const isEdit = view.kind === "edit";
    return (
      <>
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">
            {isEdit ? "edit user" : "create new user"}
          </h1>
          {backButton}
        </div>
        <ErrorBanner error={formError} />
        <form
          onSubmit={isEdit ? onSaveEdit : onCreate}
          className="bg-[#1a1a1a] border border-zinc-800/60 p-6 md:p-8 space-y-5 max-w-xl"
        >
          <div>
            <label className="auth-label">user id *</label>
            <input className="admin-input" required readOnly={isEdit} value={fId} onChange={(e) => setFId(e.target.value)} />
          </div>
          <div>
            <label className="auth-label">username *</label>
            <input className="admin-input" required value={fUsername} onChange={(e) => setFUsername(e.target.value)} />
          </div>
          <div>
            <label className="auth-label">email</label>
            <input className="admin-input" value={fEmail} onChange={(e) => setFEmail(e.target.value)} />
          </div>
          {isEdit ? (
            <>
              <div className="grid grid-cols-2 gap-3 border border-zinc-800 p-4">
                <label className="flex items-center gap-2 text-sm lowercase text-zinc-300 cursor-pointer">
                  <input type="checkbox" checked={fEmailConfirmed} onChange={(e) => setFEmailConfirmed(e.target.checked)} />
                  email confirmed
                </label>
                <label className="flex items-center gap-2 text-sm lowercase text-zinc-300 cursor-pointer">
                  <input type="checkbox" checked={fTwoFactor} onChange={(e) => setFTwoFactor(e.target.checked)} />
                  2fa enabled
                </label>
                <label className="flex items-center gap-2 text-sm lowercase text-zinc-300 cursor-pointer col-span-2">
                  <input type="checkbox" checked={fLockoutEnabled} onChange={(e) => setFLockoutEnabled(e.target.checked)} />
                  lockout enabled
                </label>
                <p className="col-span-2 text-[10px] text-zinc-500 lowercase">
                  created {view.user.created_at ? formatUTC(view.user.created_at) : "—"} · failed attempts: {view.user.access_failed_count}
                  {view.user.lockout_end ? ` · locked until ${formatUTC(view.user.lockout_end)}` : ""}
                </p>
              </div>
              <div>
                <label className="auth-label">set new password (leave empty to keep)</label>
                <input
                  className="admin-input"
                  type="password"
                  autoComplete="new-password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                />
              </div>
              {view.logins.length > 0 && (
                <div>
                  <label className="auth-label">external logins</label>
                  <div className="space-y-2">
                    {view.logins.map((l) => (
                      <div key={l.LoginProvider + l.ProviderKey} className="flex items-center justify-between border border-zinc-800 px-3 py-2 text-sm">
                        <span className="text-zinc-300 lowercase">
                          {l.ProviderName || l.LoginProvider} <span className="text-zinc-500 text-xs">({l.ProviderKey})</span>
                        </span>
                        <button type="button" className="admin-btn admin-btn-danger" onClick={() => void onRemoveLogin(view.user, l)}>
                          remove
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div>
              <label className="auth-label">initial password *</label>
              <input className="admin-input" type="password" required value={fPassword} onChange={(e) => setFPassword(e.target.value)} />
            </div>
          )}
          <div className="flex items-center justify-between pt-4 border-t border-zinc-800/60">
            <div>
              {isEdit && (
                <button type="button" className="admin-btn admin-btn-danger" onClick={() => setDeleting(view.user)}>
                  delete user
                </button>
              )}
            </div>
            <div className="flex gap-2">
              <button type="button" className="admin-btn admin-btn-ghost" onClick={() => setView({ kind: "list" })}>
                cancel
              </button>
              <button type="submit" className="admin-btn" disabled={busy}>
                {busy ? "saving…" : isEdit ? "save profile" : "register user"}
              </button>
            </div>
          </div>
        </form>
        {deleting && (
          <ConfirmDialog
            title="delete user"
            message={`are you sure you want to delete user "${deleting.username}"?`}
            confirmLabel="delete user"
            busy={busy}
            onConfirm={() => void onDelete()}
            onClose={() => setDeleting(null)}
          />
        )}
      </>
    );
  }

  if (view.kind === "claims") {
    return (
      <>
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">
            user claims — <span className="text-zinc-100">{view.user.username}</span>
          </h1>
          {backButton}
        </div>
        <p className="text-xs text-zinc-500 lowercase">claims carried in id tokens and userinfo responses.</p>
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

  if (view.kind === "roles") {
    return (
      <>
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">
            user roles — <span className="text-zinc-100">{view.user.username}</span>
          </h1>
          {backButton}
        </div>
        <section className="bg-[#1a1a1a] border border-zinc-800/60 p-6 max-w-md space-y-4">
          <ErrorBanner error={formError} />
          {view.all.length === 0 ? (
            <p className="text-sm text-zinc-500 lowercase">no roles registered. create a role first.</p>
          ) : (
            view.all.map((r) => {
              const checked = view.active.includes(r.name);
              return (
                <label key={r.id} className="flex items-center gap-3 border border-zinc-800 px-3 py-2.5 cursor-pointer hover:border-zinc-600">
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={(e) =>
                      setView({
                        ...view,
                        active: e.target.checked ? [...view.active, r.name] : view.active.filter((x) => x !== r.name),
                      })
                    }
                  />
                  <span className="text-sm lowercase">
                    <span className="text-zinc-200 block">{r.name}</span>
                    <span className="text-[10px] text-zinc-500">id: {r.id}</span>
                  </span>
                </label>
              );
            })
          )}
          <div className="flex justify-end gap-2 pt-2 border-t border-zinc-800/60">
            <button type="button" className="admin-btn admin-btn-ghost" onClick={() => setView({ kind: "list" })}>
              cancel
            </button>
            <button type="button" className="admin-btn" disabled={busy} onClick={() => void onSaveRoles()}>
              {busy ? "saving…" : "apply roles"}
            </button>
          </div>
        </section>
      </>
    );
  }

  const visible = list.items.filter(
    (u) =>
      u.username.toLowerCase().includes(search.toLowerCase()) ||
      (u.email ?? "").toLowerCase().includes(search.toLowerCase()) ||
      u.id.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <>
      <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">users</h1>
      <ErrorBanner error={list.error} />
      <ListHeader
        search={search}
        onSearch={setSearch}
        searchPlaceholder="search username, email…"
        action={
          <button type="button" className="admin-btn" onClick={openCreate}>
            + new user
          </button>
        }
      />
      {list.loading && <Loading text="loading users…" />}
      {!list.loading && (
        <>
          <DataTable
            head={
              <>
                <Th>user id</Th>
                <Th>username</Th>
                <Th>email</Th>
                <Th>2fa</Th>
                <Th>lockout</Th>
                <Th right></Th>
              </>
            }
          >
            {visible.map((u) => (
              <tr key={u.id} className="hover:bg-zinc-800/20">
                <td className="p-4 text-zinc-300 break-all">{u.id}</td>
                <td className="p-4 text-zinc-100">{u.username}</td>
                <td className="p-4 text-zinc-300">
                  {u.email || "—"}
                  {u.email_confirmed && <span className="text-emerald-400 text-xs ml-2">verified</span>}
                </td>
                <td className="p-4">{u.two_factor_enabled ? <Badge tone="zinc">enabled</Badge> : <span className="text-zinc-600 text-xs">disabled</span>}</td>
                <td className="p-4 text-xs">
                  {u.lockout_enabled ? (
                    u.lockout_end ? (
                      <span className="text-red-400">locked until {formatUTC(u.lockout_end)}</span>
                    ) : (
                      <span className="text-amber-400">enabled</span>
                    )
                  ) : (
                    <span className="text-zinc-600">no</span>
                  )}
                </td>
                <td className="p-4 text-right whitespace-nowrap space-x-2">
                  <button type="button" className="admin-btn admin-btn-ghost" onClick={() => void openEdit(u.id)}>
                    profile
                  </button>
                  <button type="button" className="admin-btn admin-btn-ghost" onClick={() => void openClaims(u)}>
                    claims
                  </button>
                  <button type="button" className="admin-btn admin-btn-ghost" onClick={() => void openRoles(u)}>
                    roles
                  </button>
                  <button type="button" className="admin-btn admin-btn-danger" onClick={() => setDeleting(u)}>
                    delete
                  </button>
                </td>
              </tr>
            ))}
            {visible.length === 0 && (
              <tr>
                <td colSpan={6} className="p-4 text-sm text-zinc-500 lowercase">
                  no users match.
                </td>
              </tr>
            )}
          </DataTable>
          <Pagination page={list.page} pageSize={list.pageSize} total={list.total} onPage={(p) => void list.load(p)} />
        </>
      )}
      {deleting && (
        <ConfirmDialog
          title="delete user"
          message={`are you sure you want to delete user "${deleting.username}"?`}
          confirmLabel="delete user"
          busy={busy}
          onConfirm={() => void onDelete()}
          onClose={() => setDeleting(null)}
        />
      )}
    </>
  );
}
