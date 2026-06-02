import { call, esc } from '../app.js';

function renderKeys(items) {
  let h = '<div class="grid grid-cols-1 gap-6">';
  h += items.map(k => `
    <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-2xl p-6 shadow-sm space-y-4 relative overflow-hidden">
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl bg-amber-500/10 text-amber-600 dark:text-amber-400 flex items-center justify-center">
            <i data-lucide="key" class="w-5 h-5"></i>
          </div>
          <div>
            <h4 class="font-bold text-lg leading-tight">Key ID: <code class="text-indigo-600 dark:text-indigo-400">${esc(k.kid)}</code></h4>
            <p class="text-xs text-zinc-400">Algorithm: <span class="font-semibold text-zinc-500 dark:text-zinc-300">${esc(k.alg)}</span> | Created At: ${new Date(k.created_at).toLocaleString()}</p>
          </div>
        </div>
        <div>
          ${k.is_active ? `
            <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 shadow-sm shadow-emerald-500/5">
              <span class="relative flex h-2 w-2">
                <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span class="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              Active OIDC Signer
            </span>
          ` : `
            <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-zinc-100 dark:bg-zinc-800 text-zinc-400 border border-zinc-200 dark:border-zinc-700">
              Retired (Validation Only)
            </span>
          `}
        </div>
      </div>
      <div class="space-y-1.5">
        <span class="text-[10px] font-semibold text-zinc-400 uppercase tracking-wider block">Public Key Certificate</span>
        <pre class="w-full p-4 bg-zinc-50 dark:bg-zinc-950/80 border border-zinc-200 dark:border-zinc-800 rounded-xl font-mono text-[10px] text-zinc-500 dark:text-zinc-400 leading-relaxed overflow-x-auto select-all whitespace-pre-wrap">${esc(k.public_pem)}</pre>
      </div>
    </div>
  `).join('');
  h += '</div>';
  return h;
}

export async function showKeys() {
  const out = document.getElementById('content');
  out.innerHTML = '<p class="text-zinc-400">loading keys…</p>';
  try {
    const r = await call('GET', '/admin/api/keys');
    out.innerHTML = renderKeys(r.items || []);
    lucide.createIcons();
  } catch(e) {
    out.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 rounded-xl p-4 text-sm font-semibold">${esc(e.message)}</div>`;
  }
}
