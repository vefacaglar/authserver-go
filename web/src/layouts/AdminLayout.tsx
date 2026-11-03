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

// Admin shell: same dark/mono/square language as the auth pages.
// Access requires a signed-in user with the admin role; the Go API
// enforces the same rule (403 for non-admins).
export default function AdminLayout({ children }: { children?: ReactNode }) {
  const { session, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#121212]">
        <Loading />
      </div>
    );
  }
  if (!session?.authenticated) {
    return <Navigate to="/login" replace />;
  }
  if (!session.is_admin) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-[#121212] px-4">
        <div className="bg-[#1a1a1a] border border-zinc-800/60 p-8 max-w-[400px] w-full">
          <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase mb-4">admin</h1>
          <p className="text-sm text-zinc-400 lowercase mb-6">
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
    `flex items-center gap-3 px-4 py-2.5 text-sm lowercase whitespace-nowrap transition-colors ${
      isActive ? "bg-zinc-300 text-zinc-950 font-bold" : "text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800/50"
    }`;

  return (
    <ToastProvider>
      <div className="min-h-screen bg-[#121212] flex flex-col md:flex-row">
        <aside className="w-full md:w-60 bg-[#1a1a1a] border-b md:border-b-0 md:border-r border-zinc-800/60 flex flex-col shrink-0">
          <div className="h-16 px-6 border-b border-zinc-800/60 flex items-center justify-between">
            <Link to="/" className="text-sm font-bold text-zinc-300 lowercase tracking-tight">
              authserver
            </Link>
            <span className="text-[10px] px-2 py-0.5 border border-zinc-700 text-zinc-400 lowercase">admin</span>
          </div>
          <nav className="flex md:flex-col gap-1 p-3 overflow-x-auto md:overflow-y-auto flex-1">
            {navItems.map((item) => (
              <NavLink key={item.to} to={item.to} end={item.end} className={linkClass}>
                <item.icon className="w-4 h-4 shrink-0" />
                {item.label}
              </NavLink>
            ))}
          </nav>
          <div className="p-4 border-t border-zinc-800/60 text-xs lowercase space-y-2 hidden md:block">
            <p className="text-zinc-500">
              signed in as <span className="text-zinc-300">{session.username}</span>
            </p>
            <div className="flex gap-4">
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
          <div className="p-6 md:p-8 space-y-6 max-w-[1400px]">{children ?? <Outlet />}</div>
        </main>
      </div>
    </ToastProvider>
  );
}
