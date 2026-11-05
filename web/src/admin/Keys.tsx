import { useCallback, useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { apiGet, apiPost } from "../lib/api";
import { Badge, CopyButton, useToast } from "./shared";
import { ConfirmDialog, ErrorBanner, Loading, errorMessage } from "../components/ui";
import { formatUTC } from "../lib/format";
import type { KeyView, Paged } from "../lib/types";

export default function Keys() {
  const toast = useToast();
  const [items, setItems] = useState<KeyView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmRotate, setConfirmRotate] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      const r = await apiGet<Paged<KeyView>>("/admin/api/keys");
      setItems(r.items ?? []);
    } catch (e) {
      setError(errorMessage(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function onRotate() {
    setBusy(true);
    try {
      await apiPost("/admin/api/keys/rotate");
      toast("signing key rotated — previous key is now retired and kept in jwks for verification");
      setConfirmRotate(false);
      await load();
    } catch (e) {
      toast(errorMessage(e), "error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-[20px] font-semibold text-[var(--text-heading)] lowercase m-0">signing keys</h1>
          <p className="text-[13px] text-[var(--muted)] lowercase mt-1 m-0">
            rsa-2048 asymmetric keys used to sign access and id tokens. retired keys remain in jwks so existing tokens stay verifiable.
          </p>
        </div>
        <button type="button" className="admin-btn shrink-0" onClick={() => setConfirmRotate(true)}>
          <RefreshCw className="w-3.5 h-3.5" />
          rotate active key
        </button>
      </div>

      <ErrorBanner error={error} />
      {!items && !error && <Loading text="loading keys…" />}
      {items && (
        <div className="space-y-4">
          {items.map((k) => (
            <section key={k.kid} className="bg-[var(--bg)] border border-[var(--border)] p-6 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <h2 className="text-[15px] font-semibold text-[var(--text-heading)] lowercase m-0">
                      key id: {k.kid}
                    </h2>
                    <CopyButton value={k.kid} label="copy kid" />
                  </div>
                  <p className="text-xs text-[var(--muted)] lowercase m-0">
                    algorithm: {k.alg} · created: {formatUTC(k.created_at)}
                    {k.retired_at ? ` · retired: ${formatUTC(k.retired_at)}` : ""}
                  </p>
                </div>
                {k.is_active ? (
                  <Badge tone="emerald">active signer</Badge>
                ) : (
                  <Badge tone="zinc">retired (verification only)</Badge>
                )}
              </div>
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[11px] text-[var(--muted)] lowercase">public key (pem)</span>
                  <CopyButton value={k.public_pem} label="copy pem" />
                </div>
                <pre className="w-full p-4 bg-[var(--bg)] border border-[var(--border)] text-[11px] text-[var(--text)] leading-relaxed overflow-x-auto whitespace-pre-wrap select-all m-0">
                  {k.public_pem}
                </pre>
              </div>
            </section>
          ))}
          {items.length === 0 && <p className="text-sm text-[var(--muted)] lowercase">no signing keys yet.</p>}
        </div>
      )}

      {confirmRotate && (
        <ConfirmDialog
          title="rotate active signing key"
          message="rotating generates a new active rsa-2048 keypair for signing new tokens and marks the current key as retired. retired keys remain published in /.well-known/jwks.json so already-issued tokens continue to validate until they expire. continue?"
          confirmLabel="rotate key now"
          busy={busy}
          onConfirm={() => void onRotate()}
          onClose={() => setConfirmRotate(false)}
        />
      )}
    </>
  );
}
