import type { ReactNode } from "react";
import { Link, NavLink } from "react-router";
import { useAuth } from "../lib/auth";

// Signed-in shell styled after vefacaglar.com's 960px frame, minimal header, and footer mark.
export default function AppLayout({ children }: { children: ReactNode }) {
  const { session } = useAuth();
  const linkClass = ({ isActive }: { isActive: boolean }) => `nav-link${isActive ? " nav-link-active" : ""}`;

  return (
    <div className="min-h-screen bg-[var(--bg)] text-[var(--text)] flex flex-col">
      <div className="site-frame flex-1 flex flex-col justify-between">
        <header className="flex flex-wrap items-center justify-between gap-4 min-h-[60px] mt-6 mb-9 pb-4 border-b border-[var(--border)]">
          <div className="inline-flex items-center gap-2 text-[14px]">
            <Link
              to="/"
              className="text-[14px] font-semibold text-[var(--text-heading)] hover:text-[var(--accent)] no-underline transition-colors lowercase"
            >
              authserver
            </Link>
          </div>
          <nav className="flex items-center gap-6">
            <NavLink to="/" end className={linkClass}>
              home
            </NavLink>
            <NavLink to="/profile" className={linkClass}>
              my profile
            </NavLink>
            {session?.is_admin && (
              <Link to="/admin" className="nav-link">
                admin
              </Link>
            )}
            <Link to="/logout" className="nav-link">
              sign out
            </Link>
          </nav>
        </header>

        <main className="flex-1 space-y-10 pb-20">{children}</main>

        <footer className="flex items-center justify-between gap-6 py-6 border-t border-[var(--border)] text-[13px] text-[var(--muted)]">
          <span>authserver</span>
          {session?.username && <span className="lowercase">{session.username}</span>}
        </footer>
      </div>
    </div>
  );
}
