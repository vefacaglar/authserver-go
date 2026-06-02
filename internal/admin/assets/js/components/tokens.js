import { call, esc, showToast } from '../app.js';

function renderTokens(items) {
  let h = `
    <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-2xl shadow-sm overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse">
          <thead>
            <tr class="bg-zinc-50 dark:bg-zinc-950/40 border-b border-zinc-200 dark:border-zinc-800 text-zinc-400 dark:text-zinc-500 font-semibold text-xs uppercase tracking-wider">
              <th class="p-4">Token UUID</th>
              <th class="p-4">Client ID</th>
              <th class="p-4">User ID</th>
              <th class="p-4">Scope</th>
              <th class="p-4">Expires</th>
              <th class="p-4">State</th>
              <th class="p-4 text-right"></th>
            </tr>
          </thead>
          <tbody class="divide-y divide-zinc-100 dark:divide-zinc-800/60 text-sm">
  `;

  h += items.map(t => {
    let state = 'active';
    let stateClass = 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400';
    if (t.revoked_at) {
      state = 'revoked';
      stateClass = 'bg-red-500/10 text-red-600 dark:text-red-400';
    } else if (t.consumed_at) {
      state = 'rotated';
      stateClass = 'bg-amber-500/10 text-amber-600 dark:text-amber-400';
    }

    return `
      <tr class="hover:bg-zinc-50/50 dark:hover:bg-zinc-900/30 transition-colors">
        <td class="p-4"><code>${esc(t.id)}</code></td>
        <td class="p-4 font-semibold text-zinc-800 dark:text-zinc-200">${esc(t.client_id)}</td>
        <td class="p-4">${esc(t.user_id)}</td>
        <td class="p-4 max-w-xs truncate text-zinc-500 text-xs">${esc(t.scope)}</td>
        <td class="p-4 text-xs text-zinc-400">${new Date(t.expires_at).toLocaleString()}</td>
        <td class="p-4">
          <span class="px-2 py-0.5 rounded-full text-xs font-semibold ${stateClass}">
            ${state}
          </span>
        </td>
        <td class="p-4 text-right">
          ${(!t.revoked_at && !t.consumed_at) ? `
            <button class="btn-revoke-token inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-red-200 hover:bg-red-50 text-red-600 dark:border-red-900/30 dark:hover:bg-red-950/20 dark:text-red-400 font-semibold text-xs transition-colors" data-id="${esc(t.id)}">
              <i data-lucide="power" class="w-3.5 h-3.5"></i> Revoke
            </button>
          ` : ''}
        </td>
      </tr>
    `;
  }).join('');

  h += '</tbody></table></div></div>';
  return h;
}

export async function showTokens() {
  const out = document.getElementById('content');
  out.innerHTML = '<p class="text-zinc-400">loading tokens…</p>';
  try {
    const r = await call('GET', '/admin/api/refresh-tokens?page_size=100');
    out.innerHTML = renderTokens(r.items || []);
    lucide.createIcons();

    out.querySelectorAll('.btn-revoke-token').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        if (!confirm('Are you sure you want to revoke this refresh token?')) return;
        try {
          await call('POST', '/admin/api/refresh-tokens/' + encodeURIComponent(id) + '/revoke');
          showToast(`Refresh token "${id}" revoked successfully`);
          showTokens();
        } catch(e) {
          showToast(e.message, 'error');
        }
      });
    });
  } catch(e) {
    out.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 rounded-xl p-4 text-sm font-semibold">${esc(e.message)}</div>`;
  }
}
