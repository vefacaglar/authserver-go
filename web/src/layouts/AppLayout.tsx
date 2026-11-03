import type { ReactNode } from "react";
import { Link, NavLink } from "react-router";
import { useAuth } from "../lib/auth";

// Signed-in shell: top bar with the same links the old pages had
// (home / my profile / sign out), plus an admin link for admins.
export default function AppLayout({ children }: { children: ReactNode }) {
  const { session } = useAuth();
  const linkClass = ({ isActive }: { isActive: boolean }) => `nav-link${isActive ? " nav-link-active" : ""}`;

  return (
    <div className="min-h-screen bg-[#121212]">
      <header className="border-b border-zinc-800/60">
        <div className="mx-auto flex max-w-3xl items-center justify-between px-4 py-4 sm:px-6">
          <Link to="/" className="text-sm font-bold text-zinc-300 lowercase tracking-tight">
            authserver
          </Link>
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
        </div>
      </header>
      <main className="mx-auto max-w-3xl space-y-8 px-4 py-10 sm:px-6">{children}</main>
    </div>
  );
}
