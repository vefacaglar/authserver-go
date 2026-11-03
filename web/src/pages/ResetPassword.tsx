import { useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import AuthLayout from "../layouts/AuthLayout";
import { ErrorBanner, Loading, errorMessage } from "../components/ui";
import { apiGet, apiPost } from "../lib/api";

export default function ResetPassword() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";

  const [valid, setValid] = useState<boolean | null>(null);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    apiGet<{ valid: boolean }>(`/api/auth/reset-password?token=${encodeURIComponent(token)}`)
      .then((r) => {
        if (!cancelled) setValid(r.valid);
      })
      .catch(() => {
        if (!cancelled) setValid(false);
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { redirect } = await apiPost<{ redirect: string }>("/api/auth/reset-password", {
        token,
        new_password: password,
        new_password_confirm: confirm,
      });
      window.location.assign(redirect);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <AuthLayout heading="reset password">
      <ErrorBanner error={error ?? (valid === false ? "This reset link is invalid or has expired. Please request a new one." : null)} />
      {valid === null && <Loading text="checking link…" />}
      {valid === true && (
        <form className="space-y-6" onSubmit={onSubmit}>
          <div>
            <label htmlFor="new_password" className="auth-label">
              new password
            </label>
            <input
              id="new_password"
              name="new_password"
              type="password"
              autoComplete="new-password"
              required
              autoFocus
              minLength={8}
              maxLength={72}
              className="input input-lg"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <div>
            <label htmlFor="new_password_confirm" className="auth-label">
              confirm new password
            </label>
            <input
              id="new_password_confirm"
              name="new_password_confirm"
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
          <p className="text-xs text-zinc-500 lowercase">8-72 characters. all your sessions will be signed out.</p>
          <div>
            <button type="submit" className="auth-btn" disabled={busy}>
              {busy ? "saving..." : "set new password"}
            </button>
          </div>
        </form>
      )}
      {valid === false && (
        <p className="text-xs text-zinc-500 lowercase">
          <Link to="/forgot-password" className="auth-link">
            request a new link
          </Link>
          <span className="mx-2">/</span>
          <Link to="/login" className="auth-link">
            sign in
          </Link>
        </p>
      )}
    </AuthLayout>
  );
}
