import { call, esc, showToast } from '../app.js';

function renderClients(items) {
  let h = `
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
      <div class="relative max-w-sm flex-1">
        <i data-lucide="search" class="absolute left-3 top-2.5 w-4 h-4 text-zinc-400"></i>
        <input id="search-clients" type="text" placeholder="Search clients..." class="w-full pl-9 pr-4 py-2 bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 transition-all dark:text-white">
      </div>
      <button id="btn-new-client" class="flex items-center justify-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-semibold shadow-md shadow-indigo-500/10 transition-colors">
        <i data-lucide="plus-circle" class="w-4 h-4"></i> New Client
      </button>
    </div>
    <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-2xl shadow-sm overflow-hidden mt-4">
      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse">
          <thead>
            <tr class="bg-zinc-50 dark:bg-zinc-950/40 border-b border-zinc-200 dark:border-zinc-800 text-zinc-400 dark:text-zinc-500 font-semibold text-xs uppercase tracking-wider">
              <th class="p-4">client_id</th>
              <th class="p-4">name</th>
              <th class="p-4">auth</th>
              <th class="p-4">scopes</th>
              <th class="p-4">pkce</th>
              <th class="p-4">jwks</th>
              <th class="p-4 text-right"></th>
            </tr>
          </thead>
          <tbody id="clients-table-body" class="divide-y divide-zinc-100 dark:divide-zinc-800/60 text-sm">
  `;

  h += items.map(c => `
    <tr class="hover:bg-zinc-50/50 dark:hover:bg-zinc-900/30 transition-colors">
      <td class="p-4 font-semibold text-zinc-800 dark:text-zinc-100"><code>${esc(c.client_id)}</code></td>
      <td class="p-4">${esc(c.display_name)}</td>
      <td class="p-4">
        <span class="px-2 py-0.5 rounded-full text-xs font-semibold ${c.token_endpoint_auth_method === 'private_key_jwt' ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400' : 'bg-zinc-500/10 text-zinc-600 dark:text-zinc-400'}">
          ${esc(c.token_endpoint_auth_method)}
        </span>
      </td>
      <td class="p-4 max-w-xs truncate text-zinc-500 dark:text-zinc-400" title="${esc((c.allowed_scopes || []).join(', '))}">${esc((c.allowed_scopes || []).join(', '))}</td>
      <td class="p-4">
        <i data-lucide="${c.require_pkce ? 'check-circle' : 'minus-circle'}" class="w-5 h-5 ${c.require_pkce ? 'text-emerald-500' : 'text-zinc-400'}"></i>
      </td>
      <td class="p-4">
        <span class="px-2 py-0.5 rounded-full text-[10px] font-bold tracking-wider uppercase ${c.has_jwks ? 'bg-indigo-500/10 text-indigo-600 dark:text-indigo-400' : 'bg-zinc-200 dark:bg-zinc-800 text-zinc-400'}">
          ${c.has_jwks ? 'set' : 'none'}
        </span>
      </td>
      <td class="p-4 text-right space-x-1 whitespace-nowrap">
        <button class="btn-edit inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800 font-semibold text-xs transition-colors" data-id="${esc(c.client_id)}">
          <i data-lucide="edit-3" class="w-3.5 h-3.5"></i> Edit
        </button>
        <button class="btn-del inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-red-200 hover:bg-red-50 text-red-600 dark:border-red-900/30 dark:hover:bg-red-950/20 dark:text-red-400 font-semibold text-xs transition-colors" data-id="${esc(c.client_id)}">
          <i data-lucide="trash-2" class="w-3.5 h-3.5"></i> Delete
        </button>
      </td>
    </tr>
  `).join('');

  h += '</tbody></table></div></div>';
  return h;
}

async function clientForm(c, isEdit) {
  let allScopes = [];
  try {
    const scopeRes = await call('GET', '/admin/api/scopes');
    allScopes = scopeRes.items || [];
  } catch(err) {
    allScopes = [
      {name: 'openid', display_name: 'OpenID'},
      {name: 'profile', display_name: 'Profile'},
      {name: 'email', display_name: 'Email'},
      {name: 'offline_access', display_name: 'Offline access'}
    ];
  }

  const redirects = (c.redirect_uris || []).join('\n');
  const postLogout = (c.post_logout_redirect_uris || []).join('\n');
  const props = c.properties ? JSON.stringify(c.properties, null, 2) : '';
  const method = c.token_endpoint_auth_method || 'none';

  let h = `
    <div class="flex items-center justify-between">
      <h3 class="text-lg font-bold tracking-tight">${isEdit ? 'Edit Client Config' : 'Register New OAuth2 / OIDC Client'}</h3>
      <button id="btn-back-clients" class="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-semibold transition-colors">
        <i data-lucide="arrow-left" class="w-3.5 h-3.5"></i> Back to Clients
      </button>
    </div>
    <form id="client-form" class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-2xl p-6 md:p-8 shadow-sm space-y-6 max-w-4xl mt-4">
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <!-- Left side -->
        <div class="space-y-4">
          <div class="space-y-1">
            <label for="f-client_id" class="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Client ID *</label>
            <input id="f-client_id" value="${esc(c.client_id || '')}" ${isEdit ? 'readonly class="w-full px-3 py-2 bg-zinc-100 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm text-zinc-400 focus:outline-none"' : 'class="w-full px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white" required'}>
            <p class="text-[10px] text-zinc-400">Unique identifier of your application client</p>
          </div>
          <div class="space-y-1">
            <label for="f-display_name" class="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Display Name</label>
            <input id="f-display_name" value="${esc(c.display_name || '')}" class="w-full px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white">
          </div>
          <div class="space-y-1">
            <label for="f-redirect_uris" class="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Redirect URIs</label>
            <textarea id="f-redirect_uris" placeholder="http://localhost:8080/callback" class="w-full h-24 px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white font-mono whitespace-pre">${esc(redirects)}</textarea>
            <p class="text-[10px] text-zinc-400">Allowed OIDC callbacks (One absolute URL per line. Exact match required!)</p>
          </div>
          <div class="space-y-1">
            <label for="f-post_logout_redirect_uris" class="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Post-Logout Redirect URIs</label>
            <textarea id="f-post_logout_redirect_uris" placeholder="http://localhost:8080/" class="w-full h-20 px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white font-mono whitespace-pre">${esc(postLogout)}</textarea>
          </div>
        </div>
        <!-- Right side -->
        <div class="space-y-4">
          <!-- Scopes Checkboxes -->
          <div class="space-y-2">
            <label class="text-xs font-semibold text-zinc-400 uppercase tracking-wider block">Allowed Scopes</label>
            <div class="grid grid-cols-2 gap-2 border border-zinc-200 dark:border-zinc-800 p-3 rounded-lg bg-zinc-50 dark:bg-zinc-950/20">
              ${allScopes.map(sc => {
                const checked = (c.allowed_scopes || []).includes(sc.name) || sc.name === 'openid';
                return `
                  <label class="flex items-center gap-2 text-sm p-1 cursor-pointer hover:text-indigo-600">
                    <input type="checkbox" class="client-scope-checkbox rounded border-zinc-300 dark:border-zinc-700 text-indigo-600 focus:ring-indigo-500" value="${esc(sc.name)}" ${checked ? 'checked' : ''} ${sc.name === 'openid' ? 'disabled' : ''}>
                    <span>${esc(sc.name)}</span>
                  </label>
                `;
              }).join('')}
            </div>
          </div>
          <div class="space-y-1">
            <label for="f-auth_method" class="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Client Authentication Method</label>
            <select id="f-auth_method" class="w-full px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white">
              <option value="none" ${method === 'none' ? 'selected' : ''}>none (OIDC Public client - PKCE)</option>
              <option value="private_key_jwt" ${method === 'private_key_jwt' ? 'selected' : ''}>private_key_jwt (OIDC Confidential client)</option>
            </select>
          </div>
          <div id="jwks-field" class="space-y-1 ${method !== 'private_key_jwt' ? 'hidden' : ''}">
            <label for="f-jwks_json" class="text-xs font-semibold text-zinc-400 uppercase tracking-wider block font-mono">JWKS JSON</label>
            <textarea id="f-jwks_json" placeholder='{"keys":[{"kty":"RSA","n":"..."}]}' class="w-full h-24 px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white font-mono whitespace-pre">${esc(c.jwks_json || '')}</textarea>
            <p class="text-[10px] text-zinc-400">The public JWK set used to verify the private_key_jwt client-assertions</p>
          </div>
          <!-- Toggles -->
          <div class="space-y-2.5 pt-2">
            <label class="flex items-center gap-3 cursor-pointer">
              <input id="f-require_pkce" type="checkbox" class="rounded border-zinc-300 dark:border-zinc-700 text-indigo-600 focus:ring-indigo-500" ${c.require_pkce !== false ? 'checked' : ''}>
              <div class="text-sm">
                <p class="font-semibold text-zinc-800 dark:text-zinc-200">Require PKCE (S256 Only)</p>
                <p class="text-[10px] text-zinc-400">Strictly enforce PKCE code challenge verification</p>
              </div>
            </label>
            <label class="flex items-center gap-3 cursor-pointer">
              <input id="f-allow_refresh_tokens" type="checkbox" class="rounded border-zinc-300 dark:border-zinc-700 text-indigo-600 focus:ring-indigo-500" ${c.allow_refresh_tokens ? 'checked' : ''}>
              <div class="text-sm">
                <p class="font-semibold text-zinc-800 dark:text-zinc-200">Allow Refresh Tokens</p>
                <p class="text-[10px] text-zinc-400">Issues refresh tokens on granting offline_access</p>
              </div>
            </label>
            <label class="flex items-center gap-3 cursor-pointer">
              <input id="f-allow_client_credentials" type="checkbox" class="rounded border-zinc-300 dark:border-zinc-700 text-indigo-600 focus:ring-indigo-500" ${c.allow_client_credentials ? 'checked' : ''}>
              <div class="text-sm">
                <p class="font-semibold text-zinc-800 dark:text-zinc-200">Allow Client Credentials</p>
                <p class="text-[10px] text-zinc-400">Enables server-to-server auth flow</p>
              </div>
            </label>
          </div>
        </div>
      </div>
      <div class="h-px bg-zinc-200 dark:bg-zinc-800 my-4"></div>
      <!-- Token Lifetimes Grid -->
      <div>
        <h4 class="text-xs font-semibold text-zinc-400 uppercase tracking-wider block mb-3">Lifetimes Configuration (Seconds)</h4>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div class="space-y-1">
            <label for="f-access_lt" class="text-xs text-zinc-400">Access Token Lifetime</label>
            <input id="f-access_lt" type="number" min="0" value="${c.access_token_lifetime_seconds || ''}" class="w-full px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white" placeholder="0 = server default">
          </div>
          <div class="space-y-1">
            <label for="f-refresh_lt" class="text-xs text-zinc-400">Refresh Token Lifetime</label>
            <input id="f-refresh_lt" type="number" min="0" value="${c.refresh_token_lifetime_seconds || ''}" class="w-full px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white">
          </div>
          <div class="space-y-1">
            <label for="f-refresh_abs_lt" class="text-xs text-zinc-400">Absolute Max Lifetime</label>
            <input id="f-refresh_abs_lt" type="number" min="0" value="${c.refresh_token_absolute_lifetime_seconds || ''}" class="w-full px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white">
          </div>
        </div>
      </div>
      <div class="space-y-1 mt-4">
        <label for="f-properties" class="text-xs font-semibold text-zinc-400 uppercase tracking-wider block">Metadata Properties</label>
        <textarea id="f-properties" placeholder='{"team": "security"}' class="w-full h-20 px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-xs focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white font-mono whitespace-pre">${esc(props)}</textarea>
        <p class="text-[10px] text-zinc-400">Custom key-value pairs (Valid JSON structure required)</p>
      </div>
      <!-- Submission Buttons -->
      <div class="flex items-center justify-between pt-2 mt-4 border-t border-zinc-100 dark:border-zinc-800">
        <div>
          ${isEdit ? `
            <button type="button" id="btn-delete-client" class="px-4 py-2 border border-red-200 dark:border-red-900/30 text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20 rounded-lg text-sm font-semibold transition-colors flex items-center gap-1.5">
              <i data-lucide="trash-2" class="w-4 h-4"></i> Delete Client
            </button>
          ` : ''}
        </div>
        <div class="flex items-center gap-3">
          <button type="button" id="btn-cancel-client" class="px-4 py-2 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm font-semibold hover:bg-zinc-50 dark:hover:bg-zinc-800 transition-colors">Cancel</button>
          <button type="submit" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-semibold shadow-md shadow-indigo-500/10 transition-colors">
            ${isEdit ? 'Save Changes' : 'Register Client'}
          </button>
        </div>
      </div>
      <div id="form-error"></div>
    </form>
  `;
  return h;
}

function splitLines(s) {
  return (s || '').split(/[\n,]+/).map(x => x.trim()).filter(Boolean);
}

function readClientForm() {
  let props = {};
  const propsRaw = document.getElementById('f-properties').value.trim();
  if (propsRaw) {
    try {
      props = JSON.parse(propsRaw);
    } catch(e) {
      throw new Error('properties: ' + e.message);
    }
  }

  const scopes = ['openid'];
  document.querySelectorAll('.client-scope-checkbox:checked').forEach(cb => {
    if (cb.value !== 'openid') scopes.push(cb.value);
  });

  return {
    client_id: document.getElementById('f-client_id').value.trim(),
    display_name: document.getElementById('f-display_name').value.trim(),
    redirect_uris: splitLines(document.getElementById('f-redirect_uris').value),
    post_logout_redirect_uris: splitLines(document.getElementById('f-post_logout_redirect_uris').value),
    allowed_scopes: scopes,
    token_endpoint_auth_method: document.getElementById('f-auth_method').value,
    jwks_json: document.getElementById('f-jwks_json').value.trim(),
    require_pkce: document.getElementById('f-require_pkce').checked,
    allow_refresh_tokens: document.getElementById('f-allow_refresh_tokens').checked,
    allow_client_credentials: document.getElementById('f-allow_client_credentials').checked,
    access_token_lifetime_seconds: parseInt(document.getElementById('f-access_lt').value) || 0,
    refresh_token_lifetime_seconds: parseInt(document.getElementById('f-refresh_lt').value) || 0,
    refresh_token_absolute_lifetime_seconds: parseInt(document.getElementById('f-refresh_abs_lt').value) || 0,
    properties: Object.keys(props).length ? props : undefined
  };
}

function bindClientForm(isEdit) {
  document.getElementById('f-auth_method').addEventListener('change', function() {
    const jwksField = document.getElementById('jwks-field');
    if (this.value === 'private_key_jwt') {
      jwksField.classList.remove('hidden');
    } else {
      jwksField.classList.add('hidden');
    }
  });
  
  const goBack = () => showClients();
  document.getElementById('btn-back-clients').addEventListener('click', goBack);
  document.getElementById('btn-cancel-client').addEventListener('click', goBack);
  
  if (isEdit) {
    document.getElementById('btn-delete-client').addEventListener('click', async () => {
      const clientID = document.getElementById('f-client_id').value.trim();
      if (!confirm(`Are you absolutely sure you want to delete client "${clientID}"?`)) return;
      try {
        await call('DELETE', '/admin/api/clients/' + encodeURIComponent(clientID));
        showToast(`Client "${clientID}" deleted successfully`);
        showClients();
      } catch (err) {
        document.getElementById('form-error').innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 p-3 rounded-lg text-xs mt-3">${esc(err.message)}</div>`;
      }
    });
  }

  document.getElementById('client-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errDiv = document.getElementById('form-error');
    errDiv.textContent = '';
    try {
      const body = readClientForm();
      if (isEdit) {
        await call('PUT', '/admin/api/clients/' + encodeURIComponent(body.client_id), body);
        showToast('Client changes saved successfully');
      } else {
        await call('POST', '/admin/api/clients', body);
        showToast('Client registered successfully');
      }
      showClients();
    } catch (err) {
      errDiv.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 p-3 rounded-lg text-xs mt-3">${esc(err.message)}</div>`;
    }
  });
}

export async function showClients() {
  const out = document.getElementById('content');
  out.innerHTML = '<p class="text-zinc-400">loading clients…</p>';
  try {
    const r = await call('GET', '/admin/api/clients?page_size=100');
    out.innerHTML = renderClients(r.items || []);
    lucide.createIcons();

    // Realtime search
    const searchInput = document.getElementById('search-clients');
    const tableBody = document.getElementById('clients-table-body');
    searchInput.addEventListener('input', () => {
      const query = searchInput.value.toLowerCase().trim();
      const rows = tableBody.querySelectorAll('tr');
      rows.forEach(row => {
        const clientID = row.cells[0].textContent.toLowerCase();
        const displayName = row.cells[1].textContent.toLowerCase();
        if (clientID.includes(query) || displayName.includes(query)) {
          row.style.display = '';
        } else {
          row.style.display = 'none';
        }
      });
    });

    document.getElementById('btn-new-client').addEventListener('click', async () => {
      out.innerHTML = '<p class="text-zinc-400">preparing form…</p>';
      out.innerHTML = await clientForm({require_pkce: true}, false);
      lucide.createIcons();
      bindClientForm(false);
    });

    out.querySelectorAll('.btn-edit').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        out.innerHTML = '<p class="text-zinc-400">fetching config…</p>';
        try {
          const c = await call('GET', '/admin/api/clients/' + encodeURIComponent(id));
          out.innerHTML = await clientForm(c, true);
          lucide.createIcons();
          bindClientForm(true);
        } catch (e) {
          out.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 rounded-xl p-4 text-sm font-semibold">${esc(e.message)}</div>`;
        }
      });
    });

    out.querySelectorAll('.btn-del').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        if (!confirm(`Are you absolutely sure you want to delete client "${id}"?`)) return;
        try {
          await call('DELETE', '/admin/api/clients/' + encodeURIComponent(id));
          showToast(`Client "${id}" deleted successfully`);
          showClients();
        } catch (e) {
          showToast(e.message, 'error');
        }
      });
    });
  } catch (e) {
    out.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 rounded-xl p-4 text-sm font-semibold">${esc(e.message)}</div>`;
  }
}
