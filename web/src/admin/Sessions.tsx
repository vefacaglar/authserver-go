import { useState } from "react";
import { Badge, DataTable, Pagination, Th, usePagedList, useToast } from "./shared";
import { ConfirmDialog, ErrorBanner, Loading, errorMessage } from "../components/ui";
import { apiPost } from "../lib/api";
import { formatUTC } from "../lib/format";
import type { AdminSessionView } from "../lib/types";

export default function Sessions() {
  const list = usePagedList<AdminSessionView>("/admin/api/sessions");
  const toast = useToast();
  const [revoking, setRevoking] = useState<AdminSessionView | null>(null);
  const [busy, setBusy] = useState(false);

  async function revoke() {
    if (!revoking) return;
    setBusy(true);
    try {
      await apiPost(`/admin/api/sessions/${encodeURIComponent(revoking.id)}/revoke`);
      toast(`session revoked`);
      setRevoking(null);
      list.reload();
    } catch (e) {
      toast(errorMessage(e), "error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">sessions</h1>
      <ErrorBanner error={list.error} />
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
                <Th right></Th>
              </>
            }
          >
            {list.items.map((s) => (
              <tr key={s.id} className="hover:bg-zinc-800/20">
                <td className="p-4 text-zinc-300 break-all">{s.id}</td>
                <td className="p-4 text-zinc-200 break-all">{s.user_id}</td>
                <td className="p-4 text-xs text-zinc-400 whitespace-nowrap">{formatUTC(s.created_at)}</td>
                <td className="p-4 text-xs text-zinc-400 whitespace-nowrap">{formatUTC(s.expires_at)}</td>
                <td className="p-4">{s.revoked_at ? <Badge tone="red">revoked</Badge> : <Badge tone="emerald">active</Badge>}</td>
                <td className="p-4 text-right">
                  {!s.revoked_at && (
                    <button type="button" className="admin-btn admin-btn-danger" onClick={() => setRevoking(s)}>
                      revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {list.items.length === 0 && (
              <tr>
                <td colSpan={6} className="p-4 text-sm text-zinc-500 lowercase">
                  no sessions yet.
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
