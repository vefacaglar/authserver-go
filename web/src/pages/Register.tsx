import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import AuthLayout from "../layouts/AuthLayout";
import { ErrorBanner, errorMessage } from "../components/ui";
import { apiPost } from "../lib/api";

export default function Register() {
  const [params] = useSearchParams();
  const returnUrl = params.get("returnUrl") ?? "";

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { redirect } = await apiPost<{ redirect: string }>("/api/auth/register", {
        username,
        email,
        password,
        password_confirm: confirm,
        return_url: returnUrl,
      });
      window.location.assign(redirect);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  const loginLink = returnUrl ? `/login?returnUrl=${encodeURIComponent(returnUrl)}` : "/login";

  return (
    <AuthLayout heading="create account">
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
          <label htmlFor="email" className="auth-label">
            email
          </label>
          <input
            id="email"
            name="email"
            type="email"
            autoComplete="email"
            required
            className="input input-lg"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
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
            autoComplete="new-password"
            required
            minLength={8}
            maxLength={72}
            className="input input-lg"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <div>
          <label htmlFor="password_confirm" className="auth-label">
            confirm password
          </label>
          <input
            id="password_confirm"
            name="password_confirm"
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
        <div className="pt-1">
          <button type="submit" className="auth-btn" disabled={busy}>
            {busy ? "registering..." : "register"}
          </button>
        </div>
      </form>

      <p className="mt-8 text-[13px] text-[var(--muted)] lowercase m-0">
        already have an account?
        <Link to={loginLink} className="auth-link ml-1.5">
          sign in
        </Link>
      </p>
    </AuthLayout>
  );
}
