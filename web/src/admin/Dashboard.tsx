import { useEffect, useState } from "react";
import { Link } from "react-router";
import { apiGet } from "../lib/api";
import { ErrorBanner, Loading, errorMessage } from "../components/ui";
import { formatUTCSeconds } from "../lib/format";
import type { AuditView, KeyView, Paged } from "../lib/types";

interface Stats {
  clients: number;
  users: number;
  sessions: number;
  activeKeys: number;
  audit: AuditView[];
}

function StatCard({ label, value, to }: { label: string; value: number; to: string }) {
  return (
    <Link
      to={to}
      className="bg-[var(--bg)] border border-[var(--border)] p-5 block no-underline hover:border-[var(--accent)] hover:-translate-y-0.5 transition-all"
    >
      <span className="text-[12px] text-[var(--muted)] lowercase">{label}</span>
      <div className="text-3xl font-semibold text-[var(--text-heading)] mt-1 tabular-nums">{value}</div>
    </Link>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      apiGet<Paged<unknown>>("/admin/api/clients?page_size=1"),
      apiGet<Paged<unknown>>("/admin/api/users?page_size=1"),
      apiGet<Paged<unknown>>("/admin/api/sessions?page_size=1"),
      apiGet<Paged<KeyView>>("/admin/api/keys"),
      apiGet<Paged<AuditView>>("/admin/api/audit?page_size=5"),
    ])
      .then(([clients, users, sessions, keys, audit]) =>
        setStats({
          clients: clients.total_count ?? 0,
          users: users.total_count ?? 0,
          sessions: sessions.total_count ?? 0,
          activeKeys: (keys.items ?? []).filter((k) => k.is_active).length,
          audit: audit.items ?? [],
        }),
      )
      .catch((e) => setError(errorMessage(e)));
  }, []);

  return (
    <>
      <h1 className="text-[20px] font-semibold text-[var(--text-heading)] lowercase m-0">overview</h1>
      <ErrorBanner error={error} />
      {!stats && !error && <Loading />}
      {stats && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard label="clients" value={stats.clients} to="/admin/clients" />
            <StatCard label="total users" value={stats.users} to="/admin/users" />
            <StatCard label="sessions" value={stats.sessions} to="/admin/sessions" />
            <StatCard label="active signing keys" value={stats.activeKeys} to="/admin/keys" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <section className="bg-[var(--bg)] border border-[var(--border)] p-6">
              <h2 className="text-[15px] font-semibold text-[var(--text-heading)] lowercase mb-4 m-0">quick actions</h2>
              <div className="space-y-2.5 text-[13px] lowercase">
                <Link
                  to="/admin/clients"
                  state={{ create: true }}
                  className="block border border-[var(--border)] px-3.5 py-2.5 text-[var(--text)] no-underline hover:border-[var(--accent)] hover:text-[var(--text-heading)] transition-colors"
                >
                  — register new client
                </Link>
                <Link
                  to="/admin/users"
                  state={{ create: true }}
                  className="block border border-[var(--border)] px-3.5 py-2.5 text-[var(--text)] no-underline hover:border-[var(--accent)] hover:text-[var(--text-heading)] transition-colors"
                >
                  — create new user
                </Link>
                <Link
                  to="/admin/scopes"
                  className="block border border-[var(--border)] px-3.5 py-2.5 text-[var(--text)] no-underline hover:border-[var(--accent)] hover:text-[var(--text-heading)] transition-colors"
                >
                  — manage scopes
                </Link>
              </div>
            </section>

            <section className="lg:col-span-2 bg-[var(--bg)] border border-[var(--border)] p-6">
              <div className="flex items-center justify-between mb-4 pb-3 border-b border-[var(--border)]">
                <h2 className="text-[15px] font-semibold text-[var(--text-heading)] lowercase m-0">recent activity</h2>
                <Link to="/admin/audit" className="auth-link">
                  view all logs
                </Link>
              </div>
              {stats.audit.length === 0 ? (
                <p className="text-sm text-[var(--muted)] lowercase m-0">no activity recorded yet.</p>
              ) : (
                <div className="divide-y divide-[var(--border)]">
                  {stats.audit.map((log) => (
                    <div key={log.id} className="py-3 flex items-baseline justify-between gap-4 text-[13px]">
                      <div className="min-w-0">
                        <span className="text-[var(--text-heading)] font-semibold">{log.action}</span>
                        <span className="text-[var(--muted)] text-xs ml-3">
                          actor: {log.actor_user_id || "—"} · target: {log.target_type}:{log.target_id}
                        </span>
                      </div>
                      <span className="text-xs text-[var(--muted)] whitespace-nowrap tabular-nums">
                        {formatUTCSeconds(log.timestamp)}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </section>
          </div>
        </>
      )}
    </>
  );
}
