import { useEffect, useState, type FormEvent } from "react";
import { useLocation } from "react-router";
import { Plus, Unlock } from "lucide-react";
import {
  Badge,
  ClaimsEditor,
  CopyButton,
  DataTable,
  ListHeader,
  Pagination,
  Tabs,
  Th,
  ToggleCard,
  usePagedList,
  useToast,
  type ClaimRow,
} from "./shared";
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

type UserTab = "profile" | "roles" | "claims";

type View =
  | { kind: "list" }
  | { kind: "create" }
  | {
      kind: "detail";
      tab: UserTab;
      user: UserView;
      logins: UserLogin[];
      claims: ClaimRow[];
      allRoles: RoleView[];
      activeRoles: string[];
    };

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
  const [fLockoutEnabled, setFLockoutEnabled] = useState(true);
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
    setFEmailConfirmed(true);
    setFLockoutEnabled(true);
    setFormError(null);
    setView({ kind: "create" });
  }

  async function openDetail(id: string, initialTab: UserTab = "profile") {
    setFormError(null);
    try {
      const [user, loginsRes, claimsRes, rolesRes, userRolesRes] = await Promise.all([
        apiGet<UserView>(`/admin/api/users/${encodeURIComponent(id)}`),
        apiGet<{ logins: UserLogin[] }>(`/admin/api/users/${encodeURIComponent(id)}/logins`).catch(() => ({ logins: [] })),
        apiGet<{ claims: ClaimRow[] }>(`/admin/api/users/${encodeURIComponent(id)}/claims`).catch(() => ({ claims: [] })),
        apiGet<Paged<RoleView>>("/admin/api/roles").catch(() => ({ items: [], total_count: 0 })),
        apiGet<{ roles: string[] }>(`/admin/api/users/${encodeURIComponent(id)}/roles`).catch(() => ({ roles: [] })),
      ]);
      setFId(user.id);
      setFUsername(user.username);
      setFEmail(user.email);
      setFEmailConfirmed(user.email_confirmed);
      setFTwoFactor(user.two_factor_enabled);
      setFLockoutEnabled(user.lockout_enabled);
      setNewPassword("");
      setView({
        kind: "detail",
        tab: initialTab,
        user,
        logins: loginsRes.logins ?? [],
        claims: claimsRes.claims?.length ? claimsRes.claims : [{ Type: "", Value: "" }],
        allRoles: rolesRes.items ?? [],
        activeRoles: userRolesRes.roles ?? [],
      });
    } catch (e) {
      toast(errorMessage(e), "error");
    }
  }

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setFormError(null);
    try {
      const created = await apiPost<UserView>("/admin/api/users", {
        id: fId.trim(),
        username: fUsername.trim(),
        email: fEmail.trim(),
        password: fPassword,
      });
      if (fEmailConfirmed || fLockoutEnabled) {
        await apiPut(`/admin/api/users/${encodeURIComponent(created.id)}`, {
          username: created.username,
          email: created.email,
          email_confirmed: fEmailConfirmed,
          two_factor_enabled: false,
          lockout_enabled: fLockoutEnabled,
          access_failed_count: 0,
        });
      }
      toast("user account created");
      list.reload();
      await openDetail(created.id, "profile");
    } catch (err) {
      setFormError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function onSaveProfile(e: FormEvent) {
    e.preventDefault();
    if (view.kind !== "detail") return;
    setBusy(true);
    setFormError(null);
    try {
      const updated = await apiPut<UserView>(`/admin/api/users/${encodeURIComponent(view.user.id)}`, {
        username: fUsername.trim(),
        email: fEmail.trim(),
        email_confirmed: fEmailConfirmed,
        two_factor_enabled: fTwoFactor,
        lockout_enabled: fLockoutEnabled,
        lockout_end: view.user.lockout_end ?? null,
        access_failed_count: view.user.access_failed_count,
      });
      let revoked: number | null = null;
      if (newPassword) {
        const r = await apiPost<{ sessions_revoked: number }>(
          `/admin/api/users/${encodeURIComponent(view.user.id)}/password`,
          { password: newPassword },
        );
        revoked = r.sessions_revoked;
        setNewPassword("");
      }
      setView({ ...view, user: updated });
      toast(revoked === null ? "user profile saved" : `user profile saved — password reset, ${revoked} session(s) signed out`);
      list.reload();
    } catch (err) {
      setFormError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function onUnlockUser() {
    if (view.kind !== "detail") return;
    setBusy(true);
    setFormError(null);
    try {
      const updated = await apiPost<UserView>(`/admin/api/users/${encodeURIComponent(view.user.id)}/unlock`);
      setView({ ...view, user: updated });
      toast("user lockout cleared and failed attempts reset");
      list.reload();
    } catch (e) {
      setFormError(errorMessage(e));
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
    if (view.kind !== "detail") return;
    const rows = view.claims.filter((r) => r.Type.trim() !== "" || r.Value.trim() !== "");
    if (rows.some((r) => r.Type.trim() === "" || r.Value.trim() === "")) {
      setFormError("both claim type and value are required.");
      return;
    }
    setBusy(true);
    setFormError(null);
    try {
      await apiPut(`/admin/api/users/${encodeURIComponent(view.user.id)}/claims`, { claims: rows });
      toast("user claims updated");
    } catch (e) {
      setFormError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  async function onSaveRoles() {
    if (view.kind !== "detail") return;
    setBusy(true);
    setFormError(null);
    try {
      await apiPut(`/admin/api/users/${encodeURIComponent(view.user.id)}/roles`, { roles: view.activeRoles });
      toast("user roles updated");
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
      await openDetail(user.id, "profile");
    } catch (e) {
      toast(errorMessage(e), "error");
    }
  }

  if (view.kind === "create") {
    return (
      <form onSubmit={onCreate} className="space-y-6 max-w-2xl">
        <div className="flex items-center justify-between pb-4 border-b border-zinc-800">
          <div>
            <div className="flex items-center gap-3">
              <button
                type="button"
                className="text-xs text-zinc-500 hover:text-zinc-200 lowercase"
                onClick={() => setView({ kind: "list" })}
              >
                ← users
              </button>
              <span className="text-zinc-700">/</span>
              <h1 className="text-lg font-bold text-zinc-200 tracking-tight lowercase">create new user</h1>
            </div>
            <p className="text-xs text-zinc-500 lowercase mt-0.5">
              register a local user account. user id is generated automatically if left blank.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button type="button" className="admin-btn admin-btn-ghost" onClick={() => setView({ kind: "list" })}>
              cancel
            </button>
            <button type="submit" className="admin-btn" disabled={busy}>
              {busy ? "creating…" : "create user"}
            </button>
          </div>
        </div>

        <ErrorBanner error={formError} />

        <section className="bg-[#1a1a1a] border border-zinc-800/60 p-6 space-y-5">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="auth-label">username *</label>
              <input
                className="input"
                required
                placeholder="e.g. alice"
                value={fUsername}
                onChange={(e) => setFUsername(e.target.value)}
              />
            </div>
            <div>
              <label className="auth-label">email address</label>
              <input
                className="input"
                type="email"
                placeholder="alice@example.com"
                value={fEmail}
                onChange={(e) => setFEmail(e.target.value)}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="auth-label">initial password *</label>
              <input
                className="input"
                type="password"
                required
                autoComplete="new-password"
                value={fPassword}
                onChange={(e) => setFPassword(e.target.value)}
              />
            </div>
            <div>
              <label className="auth-label">custom user id (optional)</label>
              <input
                className="input"
                placeholder="auto-generated uuid if empty"
                value={fId}
                onChange={(e) => setFId(e.target.value)}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
            <ToggleCard
              checked={fEmailConfirmed}
              onChange={setFEmailConfirmed}
              title="mark email as verified"
              description="sets email_verified = true in id tokens and userinfo."
            />
            <ToggleCard
              checked={fLockoutEnabled}
              onChange={setFLockoutEnabled}
              title="enable brute-force lockout"
              description="temporarily locks the account after repeated failed password attempts."
            />
          </div>
        </section>

        <div className="flex justify-end gap-2">
          <button type="button" className="admin-btn admin-btn-ghost" onClick={() => setView({ kind: "list" })}>
            cancel
          </button>
          <button type="submit" className="admin-btn" disabled={busy}>
            {busy ? "creating…" : "create user"}
          </button>
        </div>
      </form>
    );
  }

  if (view.kind === "detail") {
    const u = view.user;
    const isLocked = !!u.lockout_end && new Date(u.lockout_end).getTime() > Date.now();
    const hasFailedAttempts = u.access_failed_count > 0 || isLocked;

    return (
      <div className="space-y-6 max-w-4xl">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-zinc-800">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <button
                type="button"
                className="text-xs text-zinc-500 hover:text-zinc-200 lowercase"
                onClick={() => setView({ kind: "list" })}
              >
                ← users
              </button>
              <span className="text-zinc-700">/</span>
              <h1 className="text-lg font-bold text-zinc-200 tracking-tight lowercase">{u.username}</h1>
              {u.email_confirmed && <Badge tone="emerald">verified</Badge>}
              {isLocked && <Badge tone="red">locked out</Badge>}
            </div>
            <div className="flex items-center gap-2 text-xs text-zinc-500">
              <span>user_id: {u.id}</span>
              <CopyButton value={u.id} label="copy id" />
            </div>
          </div>
          <div className="flex items-center gap-2">
            {hasFailedAttempts && (
              <button type="button" className="admin-btn" disabled={busy} onClick={() => void onUnlockUser()}>
                <Unlock className="w-3.5 h-3.5" />
                unlock / reset attempts ({u.access_failed_count})
              </button>
            )}
            <button type="button" className="admin-btn admin-btn-danger" onClick={() => setDeleting(u)}>
              delete user…
            </button>
          </div>
        </div>

        <ErrorBanner error={formError} />

        <Tabs<UserTab>
          active={view.tab}
          onChange={(tab) => {
            setFormError(null);
            setView({ ...view, tab });
          }}
          tabs={[
            { id: "profile", label: "profile & security" },
            { id: "roles", label: "assigned roles", count: view.activeRoles.length },
            { id: "claims", label: "custom claims", count: view.claims.filter((c) => c.Type.trim()).length },
          ]}
        />

        {view.tab === "profile" && (
          <form onSubmit={onSaveProfile} className="bg-[#1a1a1a] border border-zinc-800/60 p-6 space-y-6">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="auth-label">username *</label>
                <input
                  className="input"
                  required
                  value={fUsername}
                  onChange={(e) => setFUsername(e.target.value)}
                />
              </div>
              <div>
                <label className="auth-label">email address</label>
                <input
                  className="input"
                  type="email"
                  value={fEmail}
                  onChange={(e) => setFEmail(e.target.value)}
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <ToggleCard
                checked={fEmailConfirmed}
                onChange={setFEmailConfirmed}
                title="email verified"
                description="emits email_verified: true in oidc claims."
              />
              <ToggleCard
                checked={fTwoFactor}
                onChange={setFTwoFactor}
                title="two-factor (2fa)"
                description="marks two-factor authentication enabled on this account."
              />
              <ToggleCard
                checked={fLockoutEnabled}
                onChange={setFLockoutEnabled}
                title="lockout protection"
                description={`failed attempts: ${u.access_failed_count}${isLocked && u.lockout_end ? ` · locked until ${formatUTC(u.lockout_end)}` : ""}`}
              />
            </div>

            <div className="border-t border-zinc-800/60 pt-5">
              <label className="auth-label">reset password (leave empty to keep current password)</label>
              <input
                className="input max-w-md"
                type="password"
                placeholder="enter a new password to overwrite…"
                autoComplete="new-password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
              <p className="text-[11px] text-zinc-500 lowercase mt-1">
                8-72 characters. setting a password signs the user out everywhere and revokes their refresh tokens.
              </p>
            </div>

            {view.logins.length > 0 && (
              <div className="border-t border-zinc-800/60 pt-5 space-y-2">
                <label className="auth-label">linked external identity providers</label>
                {view.logins.map((l) => (
                  <div
                    key={l.LoginProvider + l.ProviderKey}
                    className="flex items-center justify-between border border-zinc-800 bg-[#121212] px-3 py-2 text-xs"
                  >
                    <span className="text-zinc-300 lowercase">
                      {l.ProviderName || l.LoginProvider}{" "}
                      <span className="text-zinc-500">({l.ProviderKey})</span>
                    </span>
                    <button
                      type="button"
                      className="admin-btn admin-btn-danger"
                      onClick={() => void onRemoveLogin(u, l)}
                    >
                      unlink
                    </button>
                  </div>
                ))}
              </div>
            )}

            <div className="flex items-center justify-between pt-4 border-t border-zinc-800/60 text-xs text-zinc-500 lowercase">
              <span>created {u.created_at ? formatUTC(u.created_at) : "—"}</span>
              <div className="flex gap-2">
                <button type="button" className="admin-btn admin-btn-ghost" onClick={() => setView({ kind: "list" })}>
                  back
                </button>
                <button type="submit" className="admin-btn" disabled={busy}>
                  {busy ? "saving…" : "save profile"}
                </button>
              </div>
            </div>
          </form>
        )}

        {view.tab === "roles" && (
          <section className="bg-[#1a1a1a] border border-zinc-800/60 p-6 space-y-5">
            <div>
              <h2 className="text-sm font-bold text-zinc-200 lowercase">role memberships</h2>
              <p className="text-xs text-zinc-500 lowercase mt-0.5">
                toggle roles assigned to {u.username}. role claims are merged into issued tokens automatically.
              </p>
            </div>
            {view.allRoles.length === 0 ? (
              <p className="text-sm text-zinc-500 lowercase">no roles registered yet. create a role in the roles tab first.</p>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {view.allRoles.map((r) => {
                  const checked = view.activeRoles.includes(r.name);
                  return (
                    <ToggleCard
                      key={r.id}
                      checked={checked}
                      title={r.name}
                      description={`role id: ${r.id}`}
                      onChange={(next) =>
                        setView({
                          ...view,
                          activeRoles: next
                            ? [...view.activeRoles, r.name]
                            : view.activeRoles.filter((x) => x !== r.name),
                        })
                      }
                    />
                  );
                })}
              </div>
            )}
            <div className="flex justify-end gap-2 pt-4 border-t border-zinc-800/60">
              <button type="button" className="admin-btn" disabled={busy} onClick={() => void onSaveRoles()}>
                {busy ? "saving…" : "save roles"}
              </button>
            </div>
          </section>
        )}

        {view.tab === "claims" && (
          <section className="bg-[#1a1a1a] border border-zinc-800/60 p-6 space-y-5">
            <div>
              <h2 className="text-sm font-bold text-zinc-200 lowercase">user claims</h2>
              <p className="text-xs text-zinc-500 lowercase mt-0.5">
                claims included in id tokens and userinfo responses when the corresponding scope (profile, email) is granted.
              </p>
            </div>
            <ClaimsEditor rows={view.claims} onChange={(claims) => setView({ ...view, claims })} />
            <div className="flex justify-end gap-2 pt-4 border-t border-zinc-800/60">
              <button type="button" className="admin-btn" disabled={busy} onClick={() => void onSaveClaims()}>
                {busy ? "saving…" : "save claims"}
              </button>
            </div>
          </section>
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
      </div>
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
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">users</h1>
          <p className="text-xs text-zinc-500 lowercase mt-0.5">
            directory accounts, role assignments, and identity claims ({list.total} total)
          </p>
        </div>
        <button type="button" className="admin-btn" onClick={openCreate}>
          <Plus className="w-3.5 h-3.5" />
          new user
        </button>
      </div>

      <ErrorBanner error={list.error} />
      <ListHeader search={search} onSearch={setSearch} searchPlaceholder="search by username, email, or id…" />
      {list.loading && <Loading text="loading users…" />}
      {!list.loading && (
        <>
          <DataTable
            head={
              <>
                <Th>user</Th>
                <Th>email</Th>
                <Th>security</Th>
                <Th>created</Th>
                <Th right>actions</Th>
              </>
            }
          >
            {visible.map((u) => {
              const isLocked = !!u.lockout_end && new Date(u.lockout_end).getTime() > Date.now();
              return (
                <tr key={u.id} className="hover:bg-zinc-800/20">
                  <td className="p-4">
                    <button
                      type="button"
                      onClick={() => void openDetail(u.id, "profile")}
                      className="text-left group block"
                    >
                      <span className="text-zinc-100 font-bold group-hover:underline">{u.username}</span>
                      <span className="block text-xs text-zinc-500 mt-0.5">{u.id}</span>
                    </button>
                  </td>
                  <td className="p-4 text-zinc-300 text-xs">
                    {u.email || "—"}
                    {u.email_confirmed && <span className="text-emerald-400 ml-2">✓ verified</span>}
                  </td>
                  <td className="p-4 text-xs space-x-1.5">
                    {isLocked && u.lockout_end ? (
                      <Badge tone="red">locked until {formatUTC(u.lockout_end)}</Badge>
                    ) : u.access_failed_count > 0 ? (
                      <Badge tone="amber">{u.access_failed_count} failed logins</Badge>
                    ) : (
                      <Badge tone="zinc">normal</Badge>
                    )}
                    {u.two_factor_enabled && <Badge tone="emerald">2fa</Badge>}
                  </td>
                  <td className="p-4 text-xs text-zinc-500 whitespace-nowrap">
                    {u.created_at ? formatUTC(u.created_at) : "—"}
                  </td>
                  <td className="p-4 text-right whitespace-nowrap space-x-2">
                    <button
                      type="button"
                      className="admin-btn admin-btn-ghost"
                      onClick={() => void openDetail(u.id, "roles")}
                    >
                      roles
                    </button>
                    <button
                      type="button"
                      className="admin-btn admin-btn-ghost"
                      onClick={() => void openDetail(u.id, "claims")}
                    >
                      claims
                    </button>
                    <button
                      type="button"
                      className="admin-btn"
                      onClick={() => void openDetail(u.id, "profile")}
                    >
                      manage
                    </button>
                  </td>
                </tr>
              );
            })}
            {visible.length === 0 && (
              <tr>
                <td colSpan={5} className="p-6 text-sm text-zinc-500 lowercase text-center">
                  no users match.
                </td>
              </tr>
            )}
          </DataTable>
          <Pagination page={list.page} pageSize={list.pageSize} total={list.total} onPage={(p) => void list.load(p)} />
        </>
      )}
    </>
  );
}
