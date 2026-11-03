import { Fragment, useState } from "react";
import { Badge, DataTable, Pagination, Th, usePagedList } from "./shared";
import { ErrorBanner, Loading } from "../components/ui";
import { formatUTCSeconds } from "../lib/format";
import type { AuditView } from "../lib/types";

export default function Audit() {
  const list = usePagedList<AuditView>("/admin/api/audit");
  const [expanded, setExpanded] = useState<string | null>(null);

  return (
    <>
      <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">audit logs</h1>
      <ErrorBanner error={list.error} />
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
            {list.items.map((l) => (
              <Fragment key={l.id}>
                <tr className="hover:bg-zinc-800/20">
                  <td className="p-4 text-xs whitespace-nowrap text-zinc-400">{formatUTCSeconds(l.timestamp)}</td>
                  <td className="p-4 text-zinc-200">{l.action}</td>
                  <td className="p-4 text-zinc-300 break-all">{l.actor_user_id || "—"}</td>
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
                    <td colSpan={6} className="p-4 text-xs text-zinc-400 space-y-1">
                      {l.user_agent && <p>user agent: {l.user_agent}</p>}
                      {l.metadata && <p>metadata: {l.metadata}</p>}
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
            {list.items.length === 0 && (
              <tr>
                <td colSpan={6} className="p-4 text-sm text-zinc-500 lowercase">
                  no audit entries yet.
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
