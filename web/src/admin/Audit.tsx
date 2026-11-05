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
        <h1 className="text-[20px] font-semibold text-[var(--text-heading)] lowercase m-0">audit logs</h1>
        <p className="text-[13px] text-[var(--muted)] lowercase mt-1 m-0">
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
                <tr className="hover:bg-[var(--border)]/35 transition-colors">
                  <td className="p-4 text-xs whitespace-nowrap text-[var(--muted)] tabular-nums">
                    {formatUTCSeconds(l.timestamp)}
                  </td>
                  <td className="p-4 text-[var(--text-heading)] font-semibold text-xs">{l.action}</td>
                  <td className="p-4 text-[var(--text)] text-xs break-all">{l.actor_user_id || "—"}</td>
                  <td className="p-4">
                    <Badge tone="zinc">{l.target_type}</Badge>{" "}
                    <span className="text-xs text-[var(--muted)] break-all">{l.target_id}</span>
                  </td>
                  <td className="p-4 text-xs text-[var(--muted)]">{l.ip_address || "—"}</td>
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
                    <td colSpan={6} className="p-4 bg-[var(--bg)] border-t border-dashed border-[var(--border)] text-xs text-[var(--muted)] space-y-1">
                      {l.user_agent && <p className="m-0">user agent: {l.user_agent}</p>}
                      {l.metadata && <p className="m-0">metadata: {l.metadata}</p>}
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
            {visible.length === 0 && (
              <tr>
                <td colSpan={6} className="p-6 text-sm text-[var(--muted)] lowercase text-center">
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
