import { Fragment, useState } from "react";
import { Badge, DataTable, ListHeader, Pagination, Th, usePagedList } from "./shared";
import { ErrorBanner, Loading } from "../components/ui";
import { formatUTCSeconds } from "../lib/format";
import type { AuditView } from "../lib/types";

export default function Audit() {
  const list = usePagedList<AuditView>("/admin/api/audit");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  const visible = list.items.filter((l) => {
    const q = search.toLowerCase();
    return (
      l.action.toLowerCase().includes(q) ||
      (l.actor_user_id ?? "").toLowerCase().includes(q) ||
      (l.target_id ?? "").toLowerCase().includes(q) ||
      (l.ip_address ?? "").toLowerCase().includes(q)
    );
  });

  return (
    <>
      <div>
        <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">audit logs</h1>
        <p className="text-xs text-zinc-500 lowercase mt-0.5">
          security events, sign-ins, token revocations, and account changes ({list.total} total)
        </p>
      </div>
      <ErrorBanner error={list.error} />
      <ListHeader search={search} onSearch={setSearch} searchPlaceholder="filter by action, actor, target, or ip…" />
      {list.loading && <Loading text="loading audit logs…" />}
      {!list.loading && (
        <>
          <DataTable
            head={
              <>
                <Th>timestamp</Th>
                <Th>action</Th>
                <Th>actor</Th>
                <Th>target</Th>
                <Th>ip</Th>
                <Th right></Th>
              </>
            }
          >
            {visible.map((l) => (
              <Fragment key={l.id}>
                <tr className="hover:bg-zinc-800/20">
                  <td className="p-4 text-xs whitespace-nowrap text-zinc-400">{formatUTCSeconds(l.timestamp)}</td>
                  <td className="p-4 text-zinc-200 font-bold text-xs">{l.action}</td>
                  <td className="p-4 text-zinc-300 text-xs break-all">{l.actor_user_id || "—"}</td>
                  <td className="p-4">
                    <Badge tone="zinc">{l.target_type}</Badge>{" "}
                    <span className="text-xs text-zinc-400 break-all">{l.target_id}</span>
                  </td>
                  <td className="p-4 text-xs text-zinc-400">{l.ip_address || "—"}</td>
                  <td className="p-4 text-right">
                    {(l.metadata || l.user_agent) && (
                      <button
                        type="button"
                        className="auth-link"
                        onClick={() => setExpanded(expanded === l.id ? null : l.id)}
                      >
                        {expanded === l.id ? "hide" : "details"}
                      </button>
                    )}
                  </td>
                </tr>
                {expanded === l.id && (
                  <tr>
                    <td colSpan={6} className="p-4 bg-[#121212] text-xs text-zinc-400 space-y-1">
                      {l.user_agent && <p>user agent: {l.user_agent}</p>}
                      {l.metadata && <p>metadata: {l.metadata}</p>}
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
            {visible.length === 0 && (
              <tr>
                <td colSpan={6} className="p-6 text-sm text-zinc-500 lowercase text-center">
                  no audit entries match.
                </td>
              </tr>
            )}
          </DataTable>
          <Pagination page={list.page} pageSize={list.pageSize} total={list.total} onPage={(p) => void list.load(p)} />
        </>
      )}
    </>
  );
}
