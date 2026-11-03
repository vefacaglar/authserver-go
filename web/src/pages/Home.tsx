import { useEffect, useState } from "react";
import { Link } from "react-router";
import AppLayout from "../layouts/AppLayout";
import { DefinitionList, ErrorBanner, Loading, Section, errorMessage } from "../components/ui";
import { apiGet } from "../lib/api";
import { formatUTC } from "../lib/format";
import type { HomeLogin, HomeView } from "../lib/types";

function LoginTable({ rows, empty }: { rows: HomeLogin[]; empty: string }) {
  if (rows.length === 0) {
    return <p className="text-sm text-zinc-500 lowercase">{empty}</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="text-xs text-zinc-500 lowercase">
            <th className="pb-2 pr-4 font-normal">when</th>
            <th className="pb-2 pr-4 font-normal">device</th>
            <th className="pb-2 font-normal">ip address</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800/60">
          {rows.map((l, i) => (
            <tr key={i}>
              <td className="py-2 pr-4 whitespace-nowrap text-zinc-300">
                {formatUTC(l.when)}
                {l.current && <span className="ml-2 text-xs text-zinc-500 lowercase">this sign-in</span>}
              </td>
              <td className="py-2 pr-4 text-zinc-300">{l.device}</td>
              <td className="py-2 text-zinc-300 break-all">{l.ip}</td>
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
            <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">welcome, {home.username}</h1>
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
              <p className="mt-4 text-xs text-zinc-500 lowercase">if this wasn&apos;t you, change your password.</p>
            )}
          </Section>
        </>
      )}
    </AppLayout>
  );
}
