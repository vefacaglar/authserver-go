import type { ReactNode } from "react";
import { Link } from "react-router";

// Centered 400px auth container framed by vefacaglar.com's breadcrumb header and footer mark.
export default function AuthLayout({ heading, children }: { heading: string; children: ReactNode }) {
  return (
    <div className="min-h-screen bg-[var(--bg)] text-[var(--text)] flex flex-col">
      <div className="site-frame flex-1 flex flex-col justify-between">
        <header className="flex items-center justify-between min-h-[60px] mt-6 mb-9">
          <div className="inline-flex items-center gap-2 text-[14px]">
            <Link to="/" className="text-[var(--muted)] hover:text-[var(--accent)] no-underline font-medium transition-colors">
              authserver
            </Link>
            <span className="text-[var(--border)] select-none">|</span>
            <span className="text-[var(--muted)] lowercase select-none">{heading}</span>
          </div>
        </header>

        <main className="w-full max-w-[400px] mx-auto my-auto py-8">
          <div className="bg-[var(--bg)] p-8 border border-[var(--border)]">
            <div className="mb-8">
              <h1 className="text-[20px] font-semibold text-[var(--text-heading)] lowercase m-0">{heading}</h1>
            </div>
            {children}
          </div>
        </main>

        <footer className="flex items-center justify-between gap-6 py-6 text-[13px] text-[var(--muted)]">
          <span>authserver</span>
        </footer>
      </div>
    </div>
  );
}
