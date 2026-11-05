import { useState } from "react";
import { Badge, CopyButton, DataTable, ListHeader, Pagination, Th, usePagedList, useToast } from "./shared";
import { ConfirmDialog, ErrorBanner, Loading, errorMessage } from "../components/ui";
import { apiPost } from "../lib/api";
import { formatUTC } from "../lib/format";
import type { RefreshTokenView } from "../lib/types";

function tokenState(t: RefreshTokenView): {
  key: "active" | "rotated" | "expired" | "revoked";
  label: string;
  tone: "emerald" | "red" | "amber" | "zinc";
} {
  if (t.revoked_at) return { key: "revoked", label: "revoked", tone: "red" };
  if (t.consumed_at) return { key: "rotated", label: "rotated", tone: "amber" };
  if (new Date(t.expires_at).getTime() <= Date.now()) return { key: "expired", label: "expired", tone: "zinc" };
  return { key: "active", label: "active", tone: "emerald" };
}

export default function RefreshTokens() {
  const list = usePagedList<RefreshTokenView>("/admin/api/refresh-tokens");
  const toast = useToast();
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<"all" | "active" | "rotated" | "expired" | "revoked">("all");
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

  const visible = list.items.filter((t) => {
    const st = tokenState(t);
    if (filter !== "all" && st.key !== filter) return false;
    const q = search.toLowerCase();
    return (
      t.id.toLowerCase().includes(q) ||
      t.client_id.toLowerCase().includes(q) ||
      t.user_id.toLowerCase().includes(q) ||
      t.scope.toLowerCase().includes(q)
    );
  });

  return (
    <>
      <div>
        <h1 className="text-[20px] font-semibold text-[var(--text-heading)] lowercase m-0">refresh tokens</h1>
        <p className="text-[13px] text-[var(--muted)] lowercase mt-1 m-0">
          opaque rotating refresh token chains ({list.total} total)
        </p>
      </div>
      <ErrorBanner error={list.error} />
      <ListHeader
        search={search}
        onSearch={setSearch}
        searchPlaceholder="filter by client_id, user_id, or token_id…"
        filters={
          <div className="flex items-center gap-1.5">
            {(["all", "active", "rotated", "expired", "revoked"] as const).map((k) => (
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
                <Th right>actions</Th>
              </>
            }
          >
            {visible.map((t) => {
              const state = tokenState(t);
              return (
                <tr key={t.id} className="hover:bg-[var(--border)]/35 transition-colors">
                  <td className="p-4 text-[var(--text)] text-xs break-all">{t.id}</td>
                  <td className="p-4 text-[var(--text-heading)] font-semibold text-xs">{t.client_id}</td>
                  <td className="p-4 text-[var(--text)] text-xs break-all">{t.user_id}</td>
                  <td className="p-4 text-[var(--muted)] text-xs max-w-xs truncate" title={t.scope}>
                    {t.scope}
                  </td>
                  <td className="p-4 text-xs text-[var(--muted)] whitespace-nowrap">{formatUTC(t.expires_at)}</td>
                  <td className="p-4">
                    <Badge tone={state.tone}>{state.label}</Badge>
                  </td>
                  <td className="p-4 text-right whitespace-nowrap space-x-2">
                    <CopyButton value={t.id} label="id" />
                    {state.key === "active" && (
                      <button type="button" className="admin-btn admin-btn-danger" onClick={() => setRevoking(t)}>
                        revoke
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
            {visible.length === 0 && (
              <tr>
                <td colSpan={7} className="p-6 text-sm text-[var(--muted)] lowercase text-center">
                  no refresh tokens match.
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
