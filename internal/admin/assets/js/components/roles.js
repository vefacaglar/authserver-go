import { call, esc, showToast } from '../app.js';

function renderRoles(items) {
  let h = `
    <div class="flex items-center justify-between">
      <h3 class="text-lg font-bold tracking-tight">Access Control Roles</h3>
      <button id="btn-new-role" class="flex items-center justify-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-semibold shadow-md shadow-indigo-500/10 transition-colors">
        <i data-lucide="shield" class="w-4 h-4"></i> New Role
      </button>
    </div>
    <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-2xl shadow-sm overflow-hidden max-w-2xl mt-4">
      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse">
          <thead>
            <tr class="bg-zinc-50 dark:bg-zinc-950/40 border-b border-zinc-200 dark:border-zinc-800 text-zinc-400 dark:text-zinc-500 font-semibold text-xs uppercase tracking-wider">
              <th class="p-4">Role ID</th>
              <th class="p-4">Normalized Name</th>
              <th class="p-4 text-right"></th>
            </tr>
          </thead>
          <tbody class="divide-y divide-zinc-100 dark:divide-zinc-800/60 text-sm">
  `;

  h += items.map(r => `
    <tr class="hover:bg-zinc-50/50 dark:hover:bg-zinc-900/30 transition-colors">
      <td class="p-4 font-semibold text-zinc-800 dark:text-zinc-100"><code>${esc(r.id)}</code></td>
      <td class="p-4 font-semibold text-indigo-600 dark:text-indigo-400">${esc(r.name)}</td>
      <td class="p-4 text-right whitespace-nowrap space-x-1">
        <button class="btn-del-role inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-red-200 hover:bg-red-50 text-red-600 dark:border-red-900/30 dark:hover:bg-red-950/20 dark:text-red-400 font-semibold text-xs transition-colors" data-id="${esc(r.id)}">
          <i data-lucide="trash-2" class="w-3.5 h-3.5"></i> Delete
        </button>
      </td>
    </tr>
  `).join('');

  h += '</tbody></table></div></div>';
  return h;
}

function roleForm() {
  return `
    <div class="flex items-center justify-between">
      <h3 class="text-lg font-bold tracking-tight">Create Identity Role</h3>
      <button id="btn-back-roles" class="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-semibold transition-colors">
        <i data-lucide="arrow-left" class="w-3.5 h-3.5"></i> Back to Roles
      </button>
    </div>
    <form id="role-form" class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-2xl p-6 md:p-8 shadow-sm space-y-5 max-w-xl mt-4">
      <div class="space-y-1">
        <label for="f-role-id" class="text-xs font-semibold text-zinc-400 uppercase tracking-wider block">Role ID *</label>
        <input id="f-role-id" required placeholder="e.g. role-admin" class="w-full px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white">
      </div>
      <div class="space-y-1">
        <label for="f-role-name" class="text-xs font-semibold text-zinc-400 uppercase tracking-wider block">Role Name *</label>
        <input id="f-role-name" required placeholder="e.g. admin" class="w-full px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white">
        <p class="text-[10px] text-zinc-400">Roles are matched case-insensitively in claims mappings</p>
      </div>
      <div class="flex items-center justify-end gap-2 pt-4 border-t border-zinc-100 dark:border-zinc-800 mt-4">
        <button type="button" id="btn-cancel-role" class="px-4 py-2 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm font-semibold hover:bg-zinc-50 dark:hover:bg-zinc-800 transition-colors">Cancel</button>
        <button type="submit" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-semibold shadow-md shadow-indigo-500/10 transition-colors">Create Role</button>
      </div>
      <div id="form-error"></div>
    </form>
  `;
}

export async function showRoles() {
  const out = document.getElementById('content');
  out.innerHTML = '<p class="text-zinc-400">loading roles…</p>';
  try {
    const r = await call('GET', '/admin/api/roles');
    out.innerHTML = renderRoles(r.items || []);
    lucide.createIcons();

    const goBack = () => showRoles();

    document.getElementById('btn-new-role').addEventListener('click', () => {
      out.innerHTML = roleForm();
      lucide.createIcons();
      document.getElementById('btn-back-roles').addEventListener('click', goBack);
      document.getElementById('btn-cancel-role').addEventListener('click', goBack);

      document.getElementById('role-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const errDiv = document.getElementById('form-error');
        errDiv.textContent = '';
        try {
          await call('POST', '/admin/api/roles', {
            id: document.getElementById('f-role-id').value.trim(),
            name: document.getElementById('f-role-name').value.trim()
          });
          showToast('Access control role registered successfully');
          showRoles();
        } catch(err) {
          errDiv.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 p-3 rounded-lg text-xs mt-3">${esc(err.message)}</div>`;
        }
      });
    });

    out.querySelectorAll('.btn-del-role').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        if (!confirm(`Are you absolutely sure you want to delete role "${id}"?`)) return;
        try {
          await call('DELETE', '/admin/api/roles/' + encodeURIComponent(id));
          showToast(`Access role "${id}" deleted successfully`);
          showRoles();
        } catch(e) {
          showToast(e.message, 'error');
        }
      });
    });

  } catch(e) {
    out.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 rounded-xl p-4 text-sm font-semibold">${esc(e.message)}</div>`;
  }
}
