import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router";
import { useAuth } from "../lib/auth";
import { Loading } from "./ui";

// Guards signed-in pages. Anonymous visitors go to login with the
// current path as returnUrl (both "/" and "/profile" are on the
// server-side return allow-list).
export default function RequireAuth({ children }: { children: ReactNode }) {
  const { session, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[var(--bg)]">
        <Loading />
      </div>
    );
  }
  if (!session?.authenticated) {
    const target = `/login?returnUrl=${encodeURIComponent(location.pathname)}`;
    return <Navigate to={target} replace />;
  }
  return <>{children}</>;
}
