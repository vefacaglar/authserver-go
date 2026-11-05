import { useEffect, useState } from "react";
import { Link } from "react-router";
import AppLayout from "../layouts/AppLayout";
import { DefinitionList, ErrorBanner, Loading, Section, errorMessage } from "../components/ui";
import { apiGet } from "../lib/api";
import { formatUTC } from "../lib/format";
import type { HomeLogin, HomeView } from "../lib/types";

function LoginTable({ rows, empty }: { rows: HomeLogin[]; empty: string }) {
  if (rows.length === 0) {
    return <p className="text-sm text-[var(--muted)] lowercase m-0">{empty}</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[14px] border-collapse">
        <thead>
          <tr className="text-[13px] text-[var(--muted)] lowercase border-b border-[var(--border)]">
            <th className="py-2 pr-4 font-normal">when</th>
            <th className="py-2 pr-4 font-normal">device</th>
            <th className="py-2 font-normal">ip address</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--border)]">
          {rows.map((l, i) => (
            <tr key={i} className="hover:bg-[var(--border)]/35 transition-colors">
              <td className="py-3 pr-4 whitespace-nowrap text-[var(--text)]">
                {formatUTC(l.when)}
                {l.current && (
                  <span className="ml-2 px-1.5 py-0.5 text-[11px] text-[var(--success)] bg-[var(--success)]/15 lowercase">
                    this sign-in
                  </span>
                )}
              </td>
              <td className="py-3 pr-4 text-[var(--text)]">{l.device}</td>
              <td className="py-3 text-[var(--text)] break-all">{l.ip}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Home() {
  const [home, setHome] = useState<HomeView | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiGet<HomeView>("/api/account/home").then(setHome).catch((e) => setError(errorMessage(e)));
  }, []);

  return (
    <AppLayout>
      <ErrorBanner error={error} />
      {!home && !error && <Loading />}
      {home && (
        <>
          <section>
            <h1 className="text-[20px] font-semibold text-[var(--text-heading)] lowercase m-0">
              welcome, {home.username}
            </h1>
          </section>

          <Section
            title="profile"
            action={
              <Link to="/profile" className="auth-link">
                my profile
              </Link>
            }
          >
            <DefinitionList
              rows={[
                ["username", home.username],
                ["email", home.email || "—"],
              ]}
            />
          </Section>

          <Section title="recent sign-ins">
            <LoginTable rows={home.logins} empty="no sign-ins recorded yet." />
          </Section>

          <Section title="recent failed sign-ins">
            <LoginTable rows={home.failed_logins} empty="no failed sign-ins recorded." />
            {home.failed_logins.length > 0 && (
              <p className="mt-4 text-[13px] text-[var(--accent)] lowercase m-0">
                if this wasn&apos;t you, change your password.
              </p>
            )}
          </Section>
        </>
      )}
    </AppLayout>
  );
}
