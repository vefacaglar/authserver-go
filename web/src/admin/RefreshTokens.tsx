import { useState } from "react";
import { Badge, DataTable, Pagination, Th, usePagedList, useToast } from "./shared";
import { ConfirmDialog, ErrorBanner, Loading, errorMessage } from "../components/ui";
import { apiPost } from "../lib/api";
import { formatUTC } from "../lib/format";
import type { RefreshTokenView } from "../lib/types";

function tokenState(t: RefreshTokenView): { label: string; tone: "emerald" | "red" | "amber" } {
  if (t.revoked_at) return { label: "revoked", tone: "red" };
  if (t.consumed_at) return { label: "rotated", tone: "amber" };
  return { label: "active", tone: "emerald" };
}

export default function RefreshTokens() {
  const list = usePagedList<RefreshTokenView>("/admin/api/refresh-tokens");
  const toast = useToast();
  const [revoking, setRevoking] = useState<RefreshTokenView | null>(null);
  const [busy, setBusy] = useState(false);

  async function revoke() {
    if (!revoking) return;
    setBusy(true);
    try {
      await apiPost(`/admin/api/refresh-tokens/${encodeURIComponent(revoking.id)}/revoke`);
      toast("refresh token revoked");
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
      <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">refresh tokens</h1>
      <ErrorBanner error={list.error} />
      {list.loading && <Loading text="loading tokens…" />}
      {!list.loading && (
        <>
          <DataTable
            head={
              <>
                <Th>token id</Th>
                <Th>client</Th>
                <Th>user</Th>
                <Th>scope</Th>
                <Th>expires</Th>
                <Th>state</Th>
                <Th right></Th>
              </>
            }
          >
            {list.items.map((t) => {
              const state = tokenState(t);
              return (
                <tr key={t.id} className="hover:bg-zinc-800/20">
                  <td className="p-4 text-zinc-300 break-all">{t.id}</td>
                  <td className="p-4 text-zinc-200">{t.client_id}</td>
                  <td className="p-4 text-zinc-300 break-all">{t.user_id}</td>
                  <td className="p-4 text-zinc-500 text-xs max-w-xs truncate" title={t.scope}>
                    {t.scope}
                  </td>
                  <td className="p-4 text-xs text-zinc-400 whitespace-nowrap">{formatUTC(t.expires_at)}</td>
                  <td className="p-4">
                    <Badge tone={state.tone}>{state.label}</Badge>
                  </td>
                  <td className="p-4 text-right">
                    {!t.revoked_at && !t.consumed_at && (
                      <button type="button" className="admin-btn admin-btn-danger" onClick={() => setRevoking(t)}>
                        revoke
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
            {list.items.length === 0 && (
              <tr>
                <td colSpan={7} className="p-4 text-sm text-zinc-500 lowercase">
                  no refresh tokens yet.
                </td>
              </tr>
            )}
          </DataTable>
          <Pagination page={list.page} pageSize={list.pageSize} total={list.total} onPage={(p) => void list.load(p)} />
        </>
      )}
      {revoking && (
        <ConfirmDialog
          title="revoke refresh token"
          message="are you sure you want to revoke this refresh token?"
          confirmLabel="revoke token"
          busy={busy}
          onConfirm={() => void revoke()}
          onClose={() => setRevoking(null)}
        />
      )}
    </>
  );
}
