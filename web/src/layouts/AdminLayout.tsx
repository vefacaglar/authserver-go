import type { ReactNode } from "react";
import { Link, Navigate, NavLink, Outlet } from "react-router";
import {
  AppWindow,
  FileText,
  Key,
  KeyRound,
  Laptop,
  LayoutDashboard,
  RefreshCw,
  Shield,
  Users,
} from "lucide-react";
import { useAuth } from "../lib/auth";
import { Loading } from "../components/ui";
import { ToastProvider } from "../admin/shared";

const navItems = [
  { to: "/admin", label: "overview", icon: LayoutDashboard, end: true },
  { to: "/admin/clients", label: "clients", icon: AppWindow },
  { to: "/admin/scopes", label: "scopes", icon: KeyRound },
  { to: "/admin/users", label: "users", icon: Users },
  { to: "/admin/roles", label: "roles", icon: Shield },
  { to: "/admin/sessions", label: "sessions", icon: Laptop },
  { to: "/admin/refresh-tokens", label: "refresh tokens", icon: RefreshCw },
  { to: "/admin/keys", label: "signing keys", icon: Key },
  { to: "/admin/audit", label: "audit logs", icon: FileText },
];

// Admin shell using vefacaglar.com's pure black ground, #2d2d2d borders, and crisp Fira Code typography.
export default function AdminLayout({ children }: { children?: ReactNode }) {
  const { session, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[var(--bg)]">
        <Loading />
      </div>
    );
  }
  if (!session?.authenticated) {
    return <Navigate to="/login" replace />;
  }
  if (!session.is_admin) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-[var(--bg)] px-4">
        <div className="bg-[var(--bg)] border border-[var(--border)] p-8 max-w-[400px] w-full">
          <h1 className="text-[20px] font-semibold text-[var(--text-heading)] lowercase mb-4">admin</h1>
          <p className="text-sm text-[var(--muted)] lowercase mb-6">
            this area needs the admin role. you are signed in as {session.username}.
          </p>
          <Link to="/" className="auth-link">
            ← back to home
          </Link>
        </div>
      </div>
    );
  }

  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `flex items-center gap-3 px-4 py-2.5 text-[13px] lowercase whitespace-nowrap transition-colors ${
      isActive
        ? "bg-[var(--text-heading)] text-[var(--bg)] font-semibold"
        : "text-[var(--muted)] hover:text-[var(--text-heading)] hover:bg-[var(--border)]/35"
    }`;

  return (
    <ToastProvider>
      <div className="min-h-screen bg-[var(--bg)] text-[var(--text)] flex flex-col md:flex-row">
        <aside className="w-full md:w-60 bg-[var(--bg)] border-b md:border-b-0 md:border-r border-[var(--border)] flex flex-col shrink-0">
          <div className="h-16 px-6 border-b border-[var(--border)] flex items-center justify-between">
            <div className="inline-flex items-center gap-2">
              <Link
                to="/"
                className="text-[14px] font-semibold text-[var(--text-heading)] hover:text-[var(--accent)] no-underline lowercase transition-colors"
              >
                authserver
              </Link>
              <span className="text-[var(--border)] select-none">|</span>
              <span className="text-[12px] text-[var(--muted)] lowercase select-none">admin</span>
            </div>
          </div>
          <nav className="flex md:flex-col gap-1 p-3 overflow-x-auto md:overflow-y-auto flex-1">
            {navItems.map((item) => (
              <NavLink key={item.to} to={item.to} end={item.end} className={linkClass}>
                <item.icon className="w-4 h-4 shrink-0" />
                {item.label}
              </NavLink>
            ))}
          </nav>
          <div className="p-4 border-t border-[var(--border)] text-xs lowercase space-y-2.5 hidden md:block">
            <p className="text-[var(--muted)] m-0">
              signed in as <span className="text-[var(--text-heading)]">{session.username}</span>
            </p>
            <div className="flex flex-wrap gap-4">
              <a href="/.well-known/openid-configuration" target="_blank" rel="noreferrer" className="auth-link">
                discovery
              </a>
              <a href="/.well-known/jwks.json" target="_blank" rel="noreferrer" className="auth-link">
                jwks
              </a>
              <Link to="/logout" className="auth-link">
                sign out
              </Link>
            </div>
          </div>
        </aside>
        <main className="flex-1 min-w-0">
          <div className="p-6 md:p-10 space-y-8 max-w-[1400px]">{children ?? <Outlet />}</div>
        </main>
      </div>
    </ToastProvider>
  );
}
