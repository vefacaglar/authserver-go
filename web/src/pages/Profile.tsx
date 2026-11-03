import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router";
import AppLayout from "../layouts/AppLayout";
import { DefinitionList, ErrorBanner, Loading, Section, StatusBanner, errorMessage } from "../components/ui";
import { apiGet, apiPost } from "../lib/api";
import { formatUTC } from "../lib/format";
import type { ProfileView } from "../lib/types";

const statusLabels: Record<string, string> = {
  session_revoked: "The session was signed out.",
  other_sessions_revoked: "All other sessions were signed out.",
  password_changed: "Your password was changed. All other sessions were signed out.",
};

export default function Profile() {
  const navigate = useNavigate();
  const [profile, setProfile] = useState<ProfileView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [pwError, setPwError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setProfile(await apiGet<ProfileView>("/api/account/profile"));
    } catch (e) {
      setError(errorMessage(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function act(fn: () => Promise<{ status: string }>) {
    setBusy(true);
    setError(null);
    setStatus(null);
    try {
      const r = await fn();
      setStatus(statusLabels[r.status] ?? r.status);
      await load();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  async function onChangePassword(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setPwError(null);
    setStatus(null);
    setError(null);
    try {
      const r = await apiPost<{ status: string }>("/api/account/profile/password", {
        current_password: current,
        new_password: next,
        new_password_confirm: confirm,
      });
      setStatus(statusLabels[r.status] ?? r.status);
      setCurrent("");
      setNext("");
      setConfirm("");
      await load();
    } catch (err) {
      setPwError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AppLayout>
      <section>
        <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">my profile</h1>
      </section>
      <StatusBanner text={status} />
      <ErrorBanner error={error} />
      {!profile && !error && <Loading />}
      {profile && (
        <>
          <Section title="account">
            <DefinitionList
              rows={[
                ["username", profile.username],
                ["email", profile.email || "—"],
              ]}
            />
          </Section>

          <Section title="change password">
            <ErrorBanner error={pwError} />
            <form className="space-y-6" onSubmit={onChangePassword}>
              <div>
                <label htmlFor="current_password" className="auth-label">
                  current password
                </label>
                <input
                  id="current_password"
                  type="password"
                  autoComplete="current-password"
                  required
                  className="input input-lg"
                  value={current}
                  onChange={(e) => setCurrent(e.target.value)}
                />
              </div>
              <div>
                <label htmlFor="new_password" className="auth-label">
                  new password
                </label>
                <input
                  id="new_password"
                  type="password"
                  autoComplete="new-password"
                  required
                  minLength={8}
                  maxLength={72}
                  className="input input-lg"
                  value={next}
                  onChange={(e) => setNext(e.target.value)}
                />
              </div>
              <div>
                <label htmlFor="new_password_confirm" className="auth-label">
                  confirm new password
                </label>
                <input
                  id="new_password_confirm"
                  type="password"
                  autoComplete="new-password"
                  required
                  minLength={8}
                  maxLength={72}
                  className="input input-lg"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                />
              </div>
              <p className="text-xs text-zinc-500 lowercase">
                8-72 characters. changing your password signs out all your other sessions.
              </p>
              <div className="sm:w-56">
                <button type="submit" className="auth-btn" disabled={busy}>
                  {busy ? "working…" : "change password"}
                </button>
              </div>
            </form>
          </Section>

          <Section
            title="active sessions"
            action={
              profile.has_other_sessions ? (
                <button
                  type="button"
                  className="auth-link"
                  disabled={busy}
                  onClick={() => void act(() => apiPost("/api/account/profile/sessions/revoke-others", {}))}
                >
                  sign out all other sessions
                </button>
              ) : undefined
            }
          >
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="text-xs text-zinc-500 lowercase">
                    <th className="pb-2 pr-4 font-normal">signed in</th>
                    <th className="pb-2 pr-4 font-normal">expires</th>
                    <th className="pb-2 font-normal"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60">
                  {profile.sessions.map((s) => (
                    <tr key={s.id}>
                      <td className="py-2 pr-4 whitespace-nowrap text-zinc-300">{formatUTC(s.created_at)}</td>
                      <td className="py-2 pr-4 whitespace-nowrap text-zinc-300">{formatUTC(s.expires_at)}</td>
                      <td className="py-2 text-right">
                        {s.current ? (
                          <span className="text-xs text-zinc-500 lowercase">this device</span>
                        ) : (
                          <button
                            type="button"
                            className="auth-link"
                            disabled={busy}
                            onClick={() =>
                              void act(() => apiPost("/api/account/profile/sessions/revoke", { session_id: s.id }))
                            }
                          >
                            sign out
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="mt-6 text-xs text-zinc-500 lowercase">
              done here?{" "}
              <button type="button" className="auth-link" onClick={() => navigate("/logout")}>
                sign out
              </button>
            </p>
          </Section>
        </>
      )}
    </AppLayout>
  );
}
