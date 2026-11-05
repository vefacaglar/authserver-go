import { useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import AuthLayout from "../layouts/AuthLayout";
import { ErrorBanner } from "../components/ui";
import { getCSRFToken } from "../lib/api";

// RP-initiated logout confirm page. GET /connect/logout redirects here
// with the RP's parameters; the actual sign-out is a classic form POST
// to /connect/logout so the server's final redirect can leave this
// origin (to the client's post_logout_redirect_uri).
export default function Logout() {
  const [params] = useSearchParams();
  const [csrf, setCsrf] = useState("");
  const error = params.get("error");

  useEffect(() => {
    getCSRFToken(true).then(setCsrf).catch(() => setCsrf(""));
  }, []);

  return (
    <AuthLayout heading="sign out">
      <ErrorBanner error={error} />
      <p className="text-[14px] text-[var(--muted)] lowercase mb-6">are you sure you want to sign out?</p>
      <form method="post" action="/connect/logout">
        <input type="hidden" name="csrf_token" value={csrf} />
        <input type="hidden" name="post_logout_redirect_uri" value={params.get("post_logout_redirect_uri") ?? ""} />
        <input type="hidden" name="state" value={params.get("state") ?? ""} />
        <input type="hidden" name="client_id" value={params.get("client_id") ?? ""} />
        <div className="flex gap-3">
          <button type="submit" name="confirm" value="yes" className="auth-btn" disabled={!csrf}>
            sign out
          </button>
          <button type="submit" name="confirm" value="no" className="auth-btn-ghost" disabled={!csrf}>
            cancel
          </button>
        </div>
      </form>
    </AuthLayout>
  );
}
