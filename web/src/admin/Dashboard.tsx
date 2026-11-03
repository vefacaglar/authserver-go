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
    <Link to={to} className="bg-[#1a1a1a] border border-zinc-800/60 p-5 block hover:border-zinc-600 transition-colors">
      <span className="text-xs text-zinc-500 lowercase tracking-wide">{label}</span>
      <div className="text-3xl font-bold tracking-tight text-zinc-200 mt-1">{value}</div>
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
      <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">overview</h1>
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
            <section className="bg-[#1a1a1a] border border-zinc-800/60 p-6">
              <h2 className="text-xs text-zinc-500 lowercase tracking-wide mb-4">quick actions</h2>
              <div className="space-y-2 text-sm lowercase">
                <Link to="/admin/clients" state={{ create: true }} className="block border border-zinc-800 px-3 py-2.5 text-zinc-300 hover:border-zinc-600">
                  register new client →
                </Link>
                <Link to="/admin/users" state={{ create: true }} className="block border border-zinc-800 px-3 py-2.5 text-zinc-300 hover:border-zinc-600">
                  create new user →
                </Link>
                <Link to="/admin/scopes" className="block border border-zinc-800 px-3 py-2.5 text-zinc-300 hover:border-zinc-600">
                  manage scopes →
                </Link>
              </div>
            </section>

            <section className="lg:col-span-2 bg-[#1a1a1a] border border-zinc-800/60 p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xs text-zinc-500 lowercase tracking-wide">recent activity</h2>
                <Link to="/admin/audit" className="auth-link">
                  view all logs
                </Link>
              </div>
              {stats.audit.length === 0 ? (
                <p className="text-sm text-zinc-500 lowercase">no activity recorded yet.</p>
              ) : (
                <div className="divide-y divide-zinc-800/40">
                  {stats.audit.map((log) => (
                    <div key={log.id} className="py-2.5 flex items-baseline justify-between gap-4 text-sm">
                      <div className="min-w-0">
                        <span className="text-zinc-200">{log.action}</span>
                        <span className="text-zinc-500 text-xs ml-3">
                          actor: {log.actor_user_id || "—"} · target: {log.target_type}:{log.target_id}
                        </span>
                      </div>
                      <span className="text-xs text-zinc-500 whitespace-nowrap">{formatUTCSeconds(log.timestamp)}</span>
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
