import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import AuthLayout from "../layouts/AuthLayout";
import { ErrorBanner, StatusBanner, errorMessage } from "../components/ui";
import { apiPost } from "../lib/api";

export default function ForgotPassword() {
  const [identifier, setIdentifier] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await apiPost("/api/auth/forgot-password", { identifier });
      // The API deliberately answers the same way whether or not an
      // account matched, so this message is always shown.
      setSent(true);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthLayout heading="forgot password">
      {sent && (
        <StatusBanner text="if an account matches, we sent a password reset link to its email address. the link expires soon." />
      )}
      <ErrorBanner error={error} />
      <form className="space-y-6" onSubmit={onSubmit}>
        <div>
          <label htmlFor="identifier" className="auth-label">
            username or email
          </label>
          <input
            id="identifier"
            name="identifier"
            type="text"
            autoComplete="username"
            required
            autoFocus
            className="input input-lg"
            value={identifier}
            onChange={(e) => setIdentifier(e.target.value)}
          />
        </div>
        <div>
          <button type="submit" className="auth-btn" disabled={busy}>
            {busy ? "sending..." : "send reset link"}
          </button>
        </div>
      </form>

      <p className="mt-8 text-xs text-zinc-500 lowercase">
        remembered it?
        <Link to="/login" className="auth-link ml-1">
          sign in
        </Link>
      </p>
    </AuthLayout>
  );
}
