import { useEffect, useState } from "react";
import { apiGet } from "../lib/api";
import { Badge } from "./shared";
import { ErrorBanner, Loading, errorMessage } from "../components/ui";
import { formatUTC } from "../lib/format";
import type { KeyView, Paged } from "../lib/types";

export default function Keys() {
  const [items, setItems] = useState<KeyView[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiGet<Paged<KeyView>>("/admin/api/keys")
      .then((r) => setItems(r.items ?? []))
      .catch((e) => setError(errorMessage(e)));
  }, []);

  return (
    <>
      <h1 className="text-lg font-bold text-zinc-300 tracking-tight lowercase">signing keys</h1>
      <ErrorBanner error={error} />
      {!items && !error && <Loading text="loading keys…" />}
      {items && (
        <div className="space-y-4">
          {items.map((k) => (
            <section key={k.kid} className="bg-[#1a1a1a] border border-zinc-800/60 p-6 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                <div>
                  <h2 className="text-sm font-bold text-zinc-300 lowercase">
                    key id: <span className="text-zinc-100">{k.kid}</span>
                  </h2>
                  <p className="text-xs text-zinc-500 lowercase">
                    algorithm: {k.alg} · created: {formatUTC(k.created_at)}
                    {k.retired_at ? ` · retired: ${formatUTC(k.retired_at)}` : ""}
                  </p>
                </div>
                {k.is_active ? <Badge tone="emerald">active signer</Badge> : <Badge tone="zinc">retired (validation only)</Badge>}
              </div>
              <div>
                <span className="text-[10px] text-zinc-500 lowercase tracking-wide block mb-1.5">public key</span>
                <pre className="w-full p-4 bg-[#121212] border border-zinc-800/60 text-[10px] text-zinc-400 leading-relaxed overflow-x-auto whitespace-pre-wrap select-all">
                  {k.public_pem}
                </pre>
              </div>
            </section>
          ))}
          {items.length === 0 && <p className="text-sm text-zinc-500 lowercase">no signing keys yet.</p>}
        </div>
      )}
    </>
  );
}
