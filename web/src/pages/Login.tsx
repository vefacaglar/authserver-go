import { useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import AuthLayout from "../layouts/AuthLayout";
import { ErrorBanner, StatusBanner, errorMessage } from "../components/ui";
import { apiPost } from "../lib/api";
import { useAuth } from "../lib/auth";

export default function Login() {
  const [params] = useSearchParams();
  const returnUrl = params.get("returnUrl") ?? "";
  const notice = params.get("notice");
  const { session, loading } = useAuth();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Already signed in and not part of a redirect flow: go home,
  // mirroring the old server page's behaviour.
  useEffect(() => {
    if (!loading && session?.authenticated && !returnUrl) {
      window.location.replace("/");
    }
  }, [loading, session, returnUrl]);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { redirect } = await apiPost<{ redirect: string }>("/api/auth/login", {
        username,
        password,
        return_url: returnUrl,
      });
      // Full navigation: the target is usually /connect/authorize,
      // which answers with its own redirect chain.
      window.location.assign(redirect);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  const registerLink = returnUrl ? `/register?returnUrl=${encodeURIComponent(returnUrl)}` : "/register";

  return (
    <AuthLayout heading="sign in">
      {notice === "password_reset" && (
        <StatusBanner text="your password was updated. sign in with the new password." />
      )}
      <ErrorBanner error={error} />
      <form className="space-y-5" onSubmit={onSubmit}>
        <div>
          <label htmlFor="username" className="auth-label">
            username
          </label>
          <input
            id="username"
            name="username"
            type="text"
            autoComplete="username"
            required
            autoFocus
            className="input input-lg"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <div>
          <label htmlFor="password" className="auth-label">
            password
          </label>
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            className="input input-lg"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <Link to="/forgot-password" className="auth-link mt-2.5 inline-block">
            forgot password?
          </Link>
        </div>
        <div className="pt-1">
          <button type="submit" className="auth-btn" disabled={busy}>
            {busy ? "logging in..." : "sign in"}
          </button>
        </div>
      </form>

      <p className="mt-8 text-[13px] text-[var(--muted)] lowercase m-0">
        don&apos;t have an account?
        <Link to={registerLink} className="auth-link ml-1.5">
          register
        </Link>
      </p>
    </AuthLayout>
  );
}
