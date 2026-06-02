import { call, esc } from '../app.js';

export async function showDashboard() {
  const out = document.getElementById('content');
  out.innerHTML = `
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      <div class="animate-pulse bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl h-24"></div>
      <div class="animate-pulse bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl h-24"></div>
      <div class="animate-pulse bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl h-24"></div>
      <div class="animate-pulse bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl h-24"></div>
    </div>
  `;

  try {
    const [clientsRes, usersRes, sessionsRes, keysRes, auditRes] = await Promise.all([
      call('GET', '/admin/api/clients?page_size=1'),
      call('GET', '/admin/api/users?page_size=1'),
      call('GET', '/admin/api/sessions?page_size=1'),
      call('GET', '/admin/api/keys'),
      call('GET', '/admin/api/audit?page_size=5')
    ]);

    const clientsCount = clientsRes.total_count || 0;
    const usersCount = usersRes.total_count || 0;
    const sessionsCount = sessionsRes.total_count || 0;
    const activeKeys = (keysRes.items || []).filter(k => k.is_active).length;

    let h = `
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <!-- CARD 1 -->
        <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-5 rounded-2xl flex items-center justify-between shadow-sm hover:shadow-md transition-all duration-200 hover:scale-[1.02]">
          <div class="space-y-1">
            <span class="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Clients</span>
            <h3 class="text-3xl font-bold tracking-tight text-zinc-900 dark:text-white heading-font">${clientsCount}</h3>
          </div>
          <div class="w-12 h-12 rounded-xl bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 flex items-center justify-center">
            <i data-lucide="app-window" class="w-6 h-6"></i>
          </div>
        </div>
        <!-- CARD 2 -->
        <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-5 rounded-2xl flex items-center justify-between shadow-sm hover:shadow-md transition-all duration-200 hover:scale-[1.02]">
          <div class="space-y-1">
            <span class="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Total Users</span>
            <h3 class="text-3xl font-bold tracking-tight text-zinc-900 dark:text-white heading-font">${usersCount}</h3>
          </div>
          <div class="w-12 h-12 rounded-xl bg-violet-500/10 text-violet-600 dark:text-violet-400 flex items-center justify-center">
            <i data-lucide="users" class="w-6 h-6"></i>
          </div>
        </div>
        <!-- CARD 3 -->
        <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-5 rounded-2xl flex items-center justify-between shadow-sm hover:shadow-md transition-all duration-200 hover:scale-[1.02]">
          <div class="space-y-1">
            <span class="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Active Sessions</span>
            <h3 class="text-3xl font-bold tracking-tight text-zinc-900 dark:text-white heading-font">${sessionsCount}</h3>
          </div>
          <div class="w-12 h-12 rounded-xl bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 flex items-center justify-center">
            <i data-lucide="laptop" class="w-6 h-6"></i>
          </div>
        </div>
        <!-- CARD 4 -->
        <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-5 rounded-2xl flex items-center justify-between shadow-sm hover:shadow-md transition-all duration-200 hover:scale-[1.02]">
          <div class="space-y-1">
            <span class="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Active Keys</span>
            <h3 class="text-3xl font-bold tracking-tight text-zinc-900 dark:text-white heading-font">${activeKeys}</h3>
          </div>
          <div class="w-12 h-12 rounded-xl bg-amber-500/10 text-amber-600 dark:text-amber-400 flex items-center justify-center">
            <i data-lucide="key" class="w-6 h-6"></i>
          </div>
        </div>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mt-6">
        <!-- QUICK ACTIONS -->
        <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-2xl p-6 shadow-sm flex flex-col justify-between">
          <div>
            <h3 class="text-lg font-bold tracking-tight mb-1">Quick Actions</h3>
            <p class="text-xs text-zinc-400 mb-5">Common administrative tasks</p>
            <div class="space-y-2">
              <button id="qa-new-client" class="w-full flex items-center justify-between p-3 rounded-xl border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-950/40 text-left transition-colors">
                <div class="flex items-center gap-3">
                  <i data-lucide="plus-circle" class="w-4 h-4 text-indigo-500"></i>
                  <span class="text-sm font-semibold">Register New Client</span>
                </div>
                <i data-lucide="chevron-right" class="w-4 h-4 text-zinc-400"></i>
              </button>
              <button id="qa-new-user" class="w-full flex items-center justify-between p-3 rounded-xl border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-950/40 text-left transition-colors">
                <div class="flex items-center gap-3">
                  <i data-lucide="user-plus" class="w-4 h-4 text-indigo-500"></i>
                  <span class="text-sm font-semibold">Create New User</span>
                </div>
                <i data-lucide="chevron-right" class="w-4 h-4 text-zinc-400"></i>
              </button>
              <button id="qa-manage-scopes" class="w-full flex items-center justify-between p-3 rounded-xl border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-950/40 text-left transition-colors">
                <div class="flex items-center gap-3">
                  <i data-lucide="key-round" class="w-4 h-4 text-indigo-500"></i>
                  <span class="text-sm font-semibold">Manage Scopes</span>
                </div>
                <i data-lucide="chevron-right" class="w-4 h-4 text-zinc-400"></i>
              </button>
            </div>
          </div>
          <div class="pt-6 border-t border-zinc-200 dark:border-zinc-800 mt-6 text-center text-xs text-zinc-400">
            OIDC protocol standard server v1.23+
          </div>
        </div>

        <!-- RECENT AUDIT LOG TIMELINE -->
        <div class="lg:col-span-2 bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-2xl p-6 shadow-sm">
          <div class="flex items-center justify-between mb-4">
            <div>
              <h3 class="text-lg font-bold tracking-tight mb-1">Recent Activity</h3>
              <p class="text-xs text-zinc-400">Latest security audit logs</p>
            </div>
            <button id="qa-view-all-logs" class="text-xs font-semibold text-indigo-600 dark:text-indigo-400 hover:underline">View all logs</button>
          </div>
          <div class="space-y-4">
            ${(auditRes.items || []).length === 0 
              ? '<p class="text-zinc-500 text-sm">No activity recorded yet.</p>' 
              : (auditRes.items || []).map(log => `
                  <div class="flex gap-4 items-start text-sm border-b border-zinc-100 dark:border-zinc-800 pb-3 last:border-b-0 last:pb-0">
                    <div class="w-8 h-8 rounded-lg bg-zinc-100 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 flex items-center justify-center text-zinc-500 shrink-0">
                      <i data-lucide="lock" class="w-3.5 h-3.5"></i>
                    </div>
                    <div class="flex-1 space-y-0.5">
                      <p class="font-semibold text-zinc-800 dark:text-zinc-200">${esc(log.action)}</p>
                      <p class="text-xs text-zinc-400">Actor: <code class="bg-zinc-100 dark:bg-zinc-950 px-1 py-0.5 rounded text-[10px]">${esc(log.actor_user_id)}</code> | Target: <span class="font-medium text-zinc-500 dark:text-zinc-400">${esc(log.target_type)}:${esc(log.target_id)}</span></p>
                    </div>
                    <span class="text-xs text-zinc-400">${new Date(log.timestamp).toLocaleTimeString()}</span>
                  </div>
                `).join('')}
          </div>
        </div>
      </div>
    `;

    out.innerHTML = h;
    lucide.createIcons();

    // Wire actions
    document.getElementById('qa-new-client').onclick = () => document.querySelector('[data-tab=clients]').click();
    document.getElementById('qa-new-user').onclick = () => document.querySelector('[data-tab=users]').click();
    document.getElementById('qa-manage-scopes').onclick = () => document.querySelector('[data-tab=scopes]').click();
    document.getElementById('qa-view-all-logs').onclick = () => document.querySelector('[data-tab=audit]').click();

  } catch(err) {
    out.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 rounded-xl p-4 text-sm font-semibold">${esc(err.message)}</div>`;
  }
}
