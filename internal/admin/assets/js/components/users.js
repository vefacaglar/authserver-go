import { call, esc, showToast } from '../app.js';

function renderUsers(items) {
  let h = `
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
      <div class="relative max-w-sm flex-1">
        <i data-lucide="search" class="absolute left-3 top-2.5 w-4 h-4 text-zinc-400"></i>
        <input id="search-users" type="text" placeholder="Search username, email..." class="w-full pl-9 pr-4 py-2 bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 transition-all dark:text-white">
      </div>
      <button id="btn-new-user" class="flex items-center justify-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-semibold shadow-md shadow-indigo-500/10 transition-colors">
        <i data-lucide="user-plus" class="w-4 h-4"></i> New User
      </button>
    </div>
    <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-2xl shadow-sm overflow-hidden mt-4">
      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse">
          <thead>
            <tr class="bg-zinc-50 dark:bg-zinc-950/40 border-b border-zinc-200 dark:border-zinc-800 text-zinc-400 dark:text-zinc-500 font-semibold text-xs uppercase tracking-wider">
              <th class="p-4">User ID</th>
              <th class="p-4">Username</th>
              <th class="p-4">Email</th>
              <th class="p-4">2FA</th>
              <th class="p-4">Lockout</th>
              <th class="p-4 text-right"></th>
            </tr>
          </thead>
          <tbody id="users-table-body" class="divide-y divide-zinc-100 dark:divide-zinc-800/60 text-sm">
  `;

  h += items.map(u => `
    <tr class="hover:bg-zinc-50/50 dark:hover:bg-zinc-900/30 transition-colors">
      <td class="p-4 font-semibold text-zinc-800 dark:text-zinc-100"><code>${esc(u.id)}</code></td>
      <td class="p-4 font-bold text-indigo-600 dark:text-indigo-400">${esc(u.username)}</td>
      <td class="p-4">
        <div class="flex items-center gap-1.5">
          <span>${esc(u.email || '—')}</span>
          ${u.email_confirmed ? '<i data-lucide="check-circle" class="w-3.5 h-3.5 text-emerald-500" title="Email Verified"></i>' : ''}
        </div>
      </td>
      <td class="p-4">
        <span class="px-2 py-0.5 rounded-full text-xs font-semibold ${u.two_factor_enabled ? 'bg-indigo-500/10 text-indigo-600 dark:text-indigo-400' : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-400'}">
          ${u.two_factor_enabled ? 'enabled' : 'disabled'}
        </span>
      </td>
      <td class="p-4">
        ${u.lockout_enabled 
          ? (u.lockout_end 
              ? `<span class="text-red-500 text-xs font-semibold">Locked until ${new Date(u.lockout_end).toLocaleDateString()}</span>` 
              : '<span class="text-amber-500 text-xs font-semibold">Enabled</span>') 
          : '<span class="text-zinc-400 text-xs">No</span>'}
      </td>
      <td class="p-4 text-right space-x-1 whitespace-nowrap">
        <button class="btn-edit-user inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800 font-semibold text-xs transition-colors" data-id="${esc(u.id)}">
          <i data-lucide="edit-3" class="w-3.5 h-3.5"></i> Profile
        </button>
        <button class="btn-claims inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-indigo-200 text-indigo-600 dark:border-indigo-900/30 dark:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-950/20 font-semibold text-xs transition-colors" data-id="${esc(u.id)}">
          <i data-lucide="tag" class="w-3.5 h-3.5"></i> Claims
        </button>
        <button class="btn-roles inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-violet-200 text-violet-600 dark:border-violet-900/30 dark:text-violet-400 hover:bg-violet-50 dark:hover:bg-violet-950/20 font-semibold text-xs transition-colors" data-id="${esc(u.id)}">
          <i data-lucide="shield" class="w-3.5 h-3.5"></i> Roles
        </button>
        <button class="btn-del-user inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-red-200 hover:bg-red-50 text-red-600 dark:border-red-900/30 dark:hover:bg-red-950/20 dark:text-red-400 font-semibold text-xs transition-colors" data-id="${esc(u.id)}">
          <i data-lucide="trash-2" class="w-3.5 h-3.5"></i> Delete
        </button>
      </td>
    </tr>
  `).join('');

  h += '</tbody></table></div></div>';
  return h;
}

function userForm(u) {
  const isEdit = !!u;
  return `
    <div class="flex items-center justify-between">
      <h3 class="text-lg font-bold tracking-tight">${isEdit ? 'Edit User Profile' : 'Create New User Account'}</h3>
      <button id="btn-back-users" class="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-semibold transition-colors">
        <i data-lucide="arrow-left" class="w-3.5 h-3.5"></i> Back to Users
      </button>
    </div>
    <form id="user-form" class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-2xl p-6 md:p-8 shadow-sm space-y-5 max-w-xl mt-4">
      <div class="space-y-1">
        <label class="text-xs font-semibold text-zinc-400 uppercase tracking-wider block">User ID *</label>
        <input id="f-id" value="${esc(u ? u.id : '')}" ${isEdit ? 'readonly class="w-full px-3 py-2 bg-zinc-100 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm text-zinc-400 focus:outline-none"' : 'class="w-full px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white" required'}>
      </div>
      <div class="space-y-1">
        <label class="text-xs font-semibold text-zinc-400 uppercase tracking-wider block">Username *</label>
        <input id="f-username" value="${esc(u ? u.username : '')}" required class="w-full px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white">
      </div>
      <div class="space-y-1">
        <label class="text-xs font-semibold text-zinc-400 uppercase tracking-wider block">Email Address</label>
        <input id="f-email" value="${esc(u ? u.email : '')}" class="w-full px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white">
      </div>
      ${isEdit ? `
        <div class="grid grid-cols-2 gap-4 border border-zinc-100 dark:border-zinc-800 p-4 rounded-xl bg-zinc-50 dark:bg-zinc-950/20">
          <label class="flex items-center gap-2 text-sm cursor-pointer">
            <input id="f-email_confirmed" type="checkbox" class="rounded text-indigo-600" ${u.email_confirmed ? 'checked' : ''}>
            <span>Email Confirmed</span>
          </label>
          <label class="flex items-center gap-2 text-sm cursor-pointer">
            <input id="f-two_factor_enabled" type="checkbox" class="rounded text-indigo-600" ${u.two_factor_enabled ? 'checked' : ''}>
            <span>2FA Enabled</span>
          </label>
          <label class="flex items-center gap-2 text-sm cursor-pointer col-span-2">
            <input id="f-lockout_enabled" type="checkbox" class="rounded text-indigo-600" ${u.lockout_enabled ? 'checked' : ''}>
            <span>Lockout Enabled (Locks account temporarily after 5 failures)</span>
          </label>
        </div>
      ` : `
        <div class="space-y-1">
          <label class="text-xs font-semibold text-zinc-400 uppercase tracking-wider block">Initial Password *</label>
          <input id="f-password" type="password" required class="w-full px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white">
        </div>
      `}
      <div class="flex items-center justify-end gap-2 pt-4 border-t border-zinc-100 dark:border-zinc-800 mt-4">
        <button type="button" id="btn-cancel-user" class="px-4 py-2 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm font-semibold hover:bg-zinc-50 dark:hover:bg-zinc-800 transition-colors">Cancel</button>
        <button type="submit" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-semibold shadow-md shadow-indigo-500/10 transition-colors">
          ${isEdit ? 'Save Profile' : 'Register User'}
        </button>
      </div>
      <div id="form-error"></div>
    </form>
  `;
}

async function userClaimsForm(userID, claims) {
  return `
    <div class="flex items-center justify-between">
      <div>
        <h3 class="text-lg font-bold tracking-tight">OIDC Claims — User: <span class="text-indigo-600 dark:text-indigo-400">${esc(userID)}</span></h3>
        <p class="text-xs text-zinc-400">Claims carried in ID tokens & UserInfo responses</p>
      </div>
      <button id="btn-back-users" class="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-semibold transition-colors">
        <i data-lucide="arrow-left" class="w-3.5 h-3.5"></i> Back to Users
      </button>
    </div>
    <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-2xl p-6 md:p-8 shadow-sm space-y-6 max-w-2xl mt-4">
      <div class="space-y-4" id="claims-list-container"></div>
      <button id="btn-add-claim-row" class="flex items-center justify-center gap-2 px-3.5 py-2 border border-zinc-200 dark:border-zinc-800 rounded-xl text-xs font-bold hover:bg-zinc-50 dark:hover:bg-zinc-950 transition-colors">
        <i data-lucide="plus" class="w-4 h-4"></i> Add OIDC Claim
      </button>
      <div class="h-px bg-zinc-200 dark:bg-zinc-800 my-4"></div>
      <div class="flex items-center justify-end gap-2">
        <button type="button" id="btn-cancel-claims" class="px-4 py-2 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm font-semibold hover:bg-zinc-50 dark:hover:bg-zinc-800 transition-colors">Cancel</button>
        <button id="btn-save-claims" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-semibold shadow-md shadow-indigo-500/10 transition-colors">Save Claims</button>
      </div>
      <div id="claims-error"></div>
    </div>
  `;
}

function renderClaimRow(type = '', value = '') {
  return `
    <div class="flex gap-3 items-center claim-row-item">
      <input type="text" placeholder="Type (e.g. name, locale)" value="${esc(type)}" class="f-claim-type w-1/3 px-3 py-2 bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none dark:text-white" required>
      <input type="text" placeholder="Value" value="${esc(value)}" class="f-claim-val flex-1 px-3 py-2 bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none dark:text-white" required>
      <button class="btn-remove-claim p-2 hover:bg-red-50 text-red-600 rounded-lg dark:hover:bg-red-950/20 dark:text-red-400 transition-colors">
        <i data-lucide="trash" class="w-4 h-4"></i>
      </button>
    </div>
  `;
}

export async function showUsers() {
  const out = document.getElementById('content');
  out.innerHTML = '<p class="text-zinc-400">loading users…</p>';
  try {
    const r = await call('GET', '/admin/api/users?page_size=100');
    out.innerHTML = renderUsers(r.items || []);
    lucide.createIcons();

    // Realtime search
    const searchInput = document.getElementById('search-users');
    const tableBody = document.getElementById('users-table-body');
    searchInput.addEventListener('input', () => {
      const query = searchInput.value.toLowerCase().trim();
      const rows = tableBody.querySelectorAll('tr');
      rows.forEach(row => {
        const username = row.cells[1].textContent.toLowerCase();
        const email = row.cells[2].textContent.toLowerCase();
        if (username.includes(query) || email.includes(query)) {
          row.style.display = '';
        } else {
          row.style.display = 'none';
        }
      });
    });

    const goBack = () => showUsers();

    // New User
    document.getElementById('btn-new-user').addEventListener('click', () => {
      out.innerHTML = userForm(null);
      lucide.createIcons();
      document.getElementById('btn-back-users').addEventListener('click', goBack);
      document.getElementById('btn-cancel-user').addEventListener('click', goBack);

      document.getElementById('user-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const errDiv = document.getElementById('form-error');
        errDiv.textContent = '';
        try {
          await call('POST', '/admin/api/users', {
            id: document.getElementById('f-id').value.trim(),
            username: document.getElementById('f-username').value.trim(),
            email: document.getElementById('f-email').value.trim(),
            password: document.getElementById('f-password').value
          });
          showToast('User created successfully');
          showUsers();
        } catch(err) {
          errDiv.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 p-3 rounded-lg text-xs mt-3">${esc(err.message)}</div>`;
        }
      });
    });

    // Edit User Profile
    out.querySelectorAll('.btn-edit-user').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        try {
          const u = await call('GET', '/admin/api/users/' + encodeURIComponent(id));
          out.innerHTML = userForm(u);
          lucide.createIcons();
          document.getElementById('btn-back-users').addEventListener('click', goBack);
          document.getElementById('btn-cancel-user').addEventListener('click', goBack);

          document.getElementById('user-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const errDiv = document.getElementById('form-error');
            errDiv.textContent = '';
            try {
              await call('PUT', '/admin/api/users/' + encodeURIComponent(id), {
                username: document.getElementById('f-username').value.trim(),
                email: document.getElementById('f-email').value.trim(),
                email_confirmed: document.getElementById('f-email_confirmed').checked,
                two_factor_enabled: document.getElementById('f-two_factor_enabled').checked,
                lockout_enabled: document.getElementById('f-lockout_enabled').checked
              });
              showToast('User profile updated successfully');
              showUsers();
            } catch(err) {
              errDiv.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 p-3 rounded-lg text-xs mt-3">${esc(err.message)}</div>`;
            }
          });
        } catch (e) {
          showToast(e.message, 'error');
        }
      });
    });

    // Edit Dynamic Claims
    out.querySelectorAll('.btn-claims').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        out.innerHTML = '<p class="text-zinc-400">loading claims…</p>';
        try {
          const r = await call('GET', '/admin/api/users/' + encodeURIComponent(id) + '/claims');
          const claims = r.claims || [];
          
          out.innerHTML = await userClaimsForm(id, claims);
          lucide.createIcons();

          const listContainer = document.getElementById('claims-list-container');
          const appendClaim = (t = '', v = '') => {
            const div = document.createElement('div');
            div.innerHTML = renderClaimRow(t, v);
            listContainer.appendChild(div);
            
            // Bind remove trigger
            div.querySelector('.btn-remove-claim').addEventListener('click', () => {
              div.remove();
            });
            lucide.createIcons();
          };

          // Render existing
          claims.forEach(c => appendClaim(c.type, c.value));
          if (claims.length === 0) appendClaim();

          document.getElementById('btn-add-claim-row').addEventListener('click', () => appendClaim());
          document.getElementById('btn-back-users').addEventListener('click', goBack);
          document.getElementById('btn-cancel-claims').addEventListener('click', goBack);

          document.getElementById('btn-save-claims').addEventListener('click', async () => {
            const errDiv = document.getElementById('claims-error');
            errDiv.textContent = '';
            const payload = [];
            let ok = true;
            
            document.querySelectorAll('.claim-row-item').forEach(row => {
              const t = row.querySelector('.f-claim-type').value.trim();
              const v = row.querySelector('.f-claim-val').value.trim();
              if (t && v) {
                payload.push({type: t, value: v});
              } else if (t || v) {
                ok = false;
              }
            });

            if (!ok) {
              errDiv.innerHTML = '<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 p-3 rounded-lg text-xs mt-3">Both claim name and value are required.</div>';
              return;
            }

            try {
              await call('PUT', '/admin/api/users/' + encodeURIComponent(id) + '/claims', {claims: payload});
              showToast('User OIDC Claims updated successfully');
              showUsers();
            } catch(err) {
              errDiv.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 p-3 rounded-lg text-xs mt-3">${esc(err.message)}</div>`;
            }
          });

        } catch (e) {
          out.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 rounded-xl p-4 text-sm font-semibold">${esc(e.message)}</div>`;
        }
      });
    });

    // User Roles Assignment
    out.querySelectorAll('.btn-roles').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        out.innerHTML = '<p class="text-zinc-400">loading roles list…</p>';
        try {
          const [rolesRes, userRolesRes] = await Promise.all([
            call('GET', '/admin/api/roles'),
            call('GET', '/admin/api/users/' + encodeURIComponent(id) + '/roles')
          ]);
          const allRoles = rolesRes.items || [];
          const activeRoles = userRolesRes.roles || [];

          let h = `
            <div class="flex items-center justify-between">
              <div>
                <h3 class="text-lg font-bold tracking-tight">Security Roles — User: <span class="text-indigo-600 dark:text-indigo-400">${esc(id)}</span></h3>
                <p class="text-xs text-zinc-400">Manage directory group authorization roles</p>
              </div>
              <button id="btn-back-users" class="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-semibold transition-colors">
                <i data-lucide="arrow-left" class="w-3.5 h-3.5"></i> Back to Users
              </button>
            </div>
            <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-2xl p-6 md:p-8 shadow-sm space-y-6 max-w-md mt-4">
              <div class="space-y-3">
                ${allRoles.length === 0 
                  ? '<p class="text-zinc-500 text-sm">No roles registered. Create a role first.</p>' 
                  : allRoles.map(r => {
                      const checked = activeRoles.includes(r.name);
                      return `
                        <label class="flex items-center gap-3 p-3 rounded-xl border border-zinc-150 dark:border-zinc-800/80 bg-zinc-50 dark:bg-zinc-950/20 cursor-pointer hover:border-indigo-400 transition-colors">
                          <input type="checkbox" class="user-role-checkbox rounded text-indigo-600 focus:ring-indigo-500" value="${esc(r.name)}" ${checked ? 'checked' : ''}>
                          <div>
                            <p class="text-sm font-semibold">${esc(r.name)}</p>
                            <p class="text-[10px] text-zinc-400">ID: ${esc(r.id)}</p>
                          </div>
                        </label>
                      `;
                    }).join('')}
              </div>
              <div class="flex items-center justify-end gap-2 pt-4 border-t border-zinc-100 dark:border-zinc-800">
                <button type="button" id="btn-cancel-roles" class="px-4 py-2 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm font-semibold hover:bg-zinc-50 dark:hover:bg-zinc-800 transition-colors">Cancel</button>
                <button id="btn-save-roles" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-semibold shadow-md shadow-indigo-500/10 transition-colors">Apply Roles</button>
              </div>
              <div id="roles-error"></div>
            </div>
          `;
          out.innerHTML = h;
          lucide.createIcons();

          document.getElementById('btn-back-users').addEventListener('click', goBack);
          document.getElementById('btn-cancel-roles').addEventListener('click', goBack);

          document.getElementById('btn-save-roles').addEventListener('click', async () => {
            const errDiv = document.getElementById('roles-error');
            errDiv.textContent = '';
            const payload = [];
            document.querySelectorAll('.user-role-checkbox:checked').forEach(cb => {
              payload.push(cb.value);
            });

            try {
              await call('PUT', '/admin/api/users/' + encodeURIComponent(id) + '/roles', {roles: payload});
              showToast('User directory roles updated successfully');
              showUsers();
            } catch(err) {
              errDiv.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 p-3 rounded-lg text-xs mt-3">${esc(err.message)}</div>`;
            }
          });

        } catch(e) {
          out.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 rounded-xl p-4 text-sm font-semibold">${esc(e.message)}</div>`;
        }
      });
    });

    // Delete User
    out.querySelectorAll('.btn-del-user').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        if (!confirm(`Are you absolutely sure you want to delete user "${id}"?`)) return;
        try {
          await call('DELETE', '/admin/api/users/' + encodeURIComponent(id));
          showToast(`User account "${id}" deleted successfully`);
          showUsers();
        } catch (e) {
          showToast(e.message, 'error');
        }
      });
    });

  } catch(e) {
    out.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 rounded-xl p-4 text-sm font-semibold">${esc(e.message)}</div>`;
  }
}
