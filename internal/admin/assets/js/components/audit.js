import { call, esc } from '../app.js';

function renderAudit(items) {
  let h = `
    <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-2xl shadow-sm overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse">
          <thead>
            <tr class="bg-zinc-50 dark:bg-zinc-950/40 border-b border-zinc-200 dark:border-zinc-800 text-zinc-400 dark:text-zinc-500 font-semibold text-xs uppercase tracking-wider">
              <th class="p-4">Timestamp</th>
              <th class="p-4">Action Event</th>
              <th class="p-4">Actor</th>
              <th class="p-4">Target Type</th>
              <th class="p-4">Target ID</th>
              <th class="p-4">Context IP</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-zinc-100 dark:divide-zinc-800/60 text-sm">
  `;

  h += items.map(l => `
    <tr class="hover:bg-zinc-50/50 dark:hover:bg-zinc-900/30 transition-colors">
      <td class="p-4 text-xs whitespace-nowrap text-zinc-500 dark:text-zinc-400">${new Date(l.timestamp).toLocaleString()}</td>
      <td class="p-4 font-bold text-indigo-600 dark:text-indigo-400">${esc(l.action)}</td>
      <td class="p-4 font-semibold text-zinc-700 dark:text-zinc-300"><code>${esc(l.actor_user_id)}</code></td>
      <td class="p-4">
        <span class="px-2 py-0.5 rounded-full text-[10px] font-bold tracking-wider uppercase bg-zinc-100 dark:bg-zinc-800 text-zinc-500 dark:text-zinc-400 border border-zinc-250 dark:border-zinc-700/80">
          ${esc(l.target_type)}
        </span>
      </td>
      <td class="p-4 text-xs font-mono">${esc(l.target_id)}</td>
      <td class="p-4 text-xs text-zinc-400 font-mono">${esc(l.ip_address || '—')}</td>
    </tr>
  `).join('');

  h += '</tbody></table></div></div>';
  return h;
}

export async function showAudit() {
  const out = document.getElementById('content');
  out.innerHTML = '<p class="text-zinc-400">loading audit logs…</p>';
  try {
    const r = await call('GET', '/admin/api/audit?page_size=100');
    out.innerHTML = renderAudit(r.items || []);
    lucide.createIcons();
  } catch(e) {
    out.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 rounded-xl p-4 text-sm font-semibold">${esc(e.message)}</div>`;
  }
}
