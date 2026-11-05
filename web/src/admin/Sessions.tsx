import { useState } from "react";
import { Badge, CopyButton, DataTable, ListHeader, Pagination, Th, usePagedList, useToast } from "./shared";
import { ConfirmDialog, ErrorBanner, Loading, errorMessage } from "../components/ui";
import { apiPost } from "../lib/api";
import { formatUTC } from "../lib/format";
import type { AdminSessionView } from "../lib/types";

function sessionState(s: AdminSessionView): { key: "active" | "expired" | "revoked"; label: string; tone: "emerald" | "zinc" | "red" } {
  if (s.revoked_at) return { key: "revoked", label: "revoked", tone: "red" };
  if (new Date(s.expires_at).getTime() <= Date.now()) return { key: "expired", label: "expired", tone: "zinc" };
  return { key: "active", label: "active", tone: "emerald" };
}

export default function Sessions() {
  const list = usePagedList<AdminSessionView>("/admin/api/sessions");
  const toast = useToast();
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<"all" | "active" | "expired" | "revoked">("all");
  const [revoking, setRevoking] = useState<AdminSessionView | null>(null);
  const [busy, setBusy] = useState(false);

  async function revoke() {
    if (!revoking) return;
    setBusy(true);
    try {
      await apiPost(`/admin/api/sessions/${encodeURIComponent(revoking.id)}/revoke`);
      toast("session revoked");
      setRevoking(null);
      list.reload();
    } catch (e) {
      toast(errorMessage(e), "error");
    } finally {
      setBusy(false);
    }
  }

  const visible = list.items.filter((s) => {
    const st = sessionState(s);
    if (filter !== "all" && st.key !== filter) return false;
    const q = search.toLowerCase();
    return s.id.toLowerCase().includes(q) || s.user_id.toLowerCase().includes(q);
  });

  return (
    <>
      <div>
        <h1 className="text-[20px] font-semibold text-[var(--text-heading)] lowercase m-0">sessions</h1>
        <p className="text-[13px] text-[var(--muted)] lowercase mt-1 m-0">
          browser single sign-on sessions ({list.total} total)
        </p>
      </div>
      <ErrorBanner error={list.error} />
      <ListHeader
        search={search}
        onSearch={setSearch}
        searchPlaceholder="filter by user_id or session_id…"
        filters={
          <div className="flex items-center gap-1.5">
            {(["all", "active", "expired", "revoked"] as const).map((k) => (
              <button
                key={k}
                type="button"
                onClick={() => setFilter(k)}
                className={`chip ${filter === k ? "chip-active" : ""}`}
              >
                {k}
              </button>
            ))}
          </div>
        }
      />
      {list.loading && <Loading text="loading sessions…" />}
      {!list.loading && (
        <>
          <DataTable
            head={
              <>
                <Th>session id</Th>
                <Th>user id</Th>
                <Th>created</Th>
                <Th>expires</Th>
                <Th>state</Th>
                <Th right>actions</Th>
              </>
            }
          >
            {visible.map((s) => {
              const st = sessionState(s);
              return (
                <tr key={s.id} className="hover:bg-[var(--border)]/35 transition-colors">
                  <td className="p-4 text-[var(--text)] text-xs break-all">{s.id}</td>
                  <td className="p-4 text-[var(--text-heading)] text-xs break-all">{s.user_id}</td>
                  <td className="p-4 text-xs text-[var(--muted)] whitespace-nowrap">{formatUTC(s.created_at)}</td>
                  <td className="p-4 text-xs text-[var(--muted)] whitespace-nowrap">{formatUTC(s.expires_at)}</td>
                  <td className="p-4">
                    <Badge tone={st.tone}>{st.label}</Badge>
                  </td>
                  <td className="p-4 text-right whitespace-nowrap space-x-2">
                    <CopyButton value={s.id} label="id" />
                    {st.key === "active" && (
                      <button type="button" className="admin-btn admin-btn-danger" onClick={() => setRevoking(s)}>
                        revoke
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
            {visible.length === 0 && (
              <tr>
                <td colSpan={6} className="p-6 text-sm text-[var(--muted)] lowercase text-center">
                  no sessions match.
                </td>
              </tr>
            )}
          </DataTable>
          <Pagination page={list.page} pageSize={list.pageSize} total={list.total} onPage={(p) => void list.load(p)} />
        </>
      )}
      {revoking && (
        <ConfirmDialog
          title="revoke session"
          message="revoking this session will also instantly invalidate all refresh tokens issued under it. continue?"
          confirmLabel="revoke session"
          busy={busy}
          onConfirm={() => void revoke()}
          onClose={() => setRevoking(null)}
        />
      )}
    </>
  );
}
