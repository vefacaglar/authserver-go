package admin

import (
	"html/template"
	"log/slog"
	"net/http"
)

// UI serves the single-page admin shell. The page is intentionally
// minimal: a tab bar, a list area, and a small JS bootstrap that
// fetches /api/<resource> and renders rows. The JSON API is the
// real contract; this shell exists so a human operator can drive
// the API from a browser.
type UI struct {
	Template *template.Template
	Logger   *slog.Logger
}

// IndexPage returns the embedded admin shell HTML. Exported so the
// composition root in cmd/authserver and the integration tests can
// share the same template.
func IndexPage() string { return indexHTML }

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>authserver admin</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="{{ .CSRFToken }}">
<style>
  body { font-family: system-ui, sans-serif; max-width: 60rem; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.4rem; }
  nav { display: flex; gap: 1rem; margin: 1rem 0; }
  nav button { padding: 0.4rem 0.8rem; cursor: pointer; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #eee; font-size: 0.9rem; }
  th { background: #f7f7f7; }
  code { font-size: 0.85rem; }
  .err { color: #b00020; }
  .muted { color: #888; }
  .row { display: flex; gap: 0.5rem; align-items: center; margin: 0.5rem 0; }
  input, select, textarea { padding: 0.3rem 0.5rem; font-family: inherit; font-size: 0.9rem; }
  textarea { width: 100%; min-height: 4rem; font-family: monospace; }
  .token-bar { display: flex; gap: 0.5rem; align-items: center; margin-bottom: 1rem; padding: 0.5rem; background: #f7f7f7; border-radius: 4px; }
  .token-bar input { flex: 1; }
  .token-bar .status { font-size: 0.8rem; }
  .token-bar .status.ok { color: #2e7d32; }
  .token-bar .status.fail { color: #b00020; }
  .form-grid { display: grid; grid-template-columns: 12rem 1fr; gap: 0.4rem 0.8rem; align-items: start; margin: 1rem 0; }
  .form-grid label { font-weight: 600; padding-top: 0.3rem; }
  .form-grid .hint { font-size: 0.8rem; color: #888; }
  .btn-row { display: flex; gap: 0.5rem; margin: 1rem 0; }
  button { padding: 0.4rem 0.8rem; cursor: pointer; }
  .btn-danger { color: #b00020; }
</style>
</head>
<body>
<h1>authserver admin</h1>
<div class="token-bar">
  <label for="admin-token">Admin token:</label>
  <input id="admin-token" type="password" placeholder="paste token (or leave empty in anonymous mode)">
  <button id="token-save">Save</button>
  <span id="token-status" class="status"></span>
</div>
<nav>
  <button data-tab="clients">Clients</button>
  <button data-tab="scopes">Scopes</button>
  <button data-tab="users">Users</button>
  <button data-tab="roles">Roles</button>
  <button data-tab="sessions">Sessions</button>
  <button data-tab="refresh-tokens">Refresh tokens</button>
  <button data-tab="keys">Signing keys</button>
  <button data-tab="audit">Audit</button>
</nav>
<div id="content"><p class="muted">Pick a tab to begin.</p></div>

<script>
(() => {
  const csrf = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
  const tokenInput = document.getElementById('admin-token');
  const tokenStatus = document.getElementById('token-status');
  tokenInput.value = sessionStorage.getItem('admin_token') || '';
  updateTokenStatus();
  document.getElementById('token-save').addEventListener('click', () => {
    sessionStorage.setItem('admin_token', tokenInput.value);
    updateTokenStatus();
  });
  function updateTokenStatus() {
    if (tokenInput.value) { tokenStatus.textContent = 'token set'; tokenStatus.className = 'status ok'; }
    else { tokenStatus.textContent = 'no token (anonymous)'; tokenStatus.className = 'status'; }
  }
  function adminToken() { return tokenInput.value || ''; }

  async function call(method, path, body) {
    const headers = {'X-CSRF-Token': csrf};
    const tok = adminToken();
    if (tok) headers['Authorization'] = 'Bearer ' + tok;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const resp = await fetch(path, {method, headers, body: body !== undefined ? JSON.stringify(body) : undefined});
    if (resp.status === 401) {
      sessionStorage.removeItem('admin_token');
      tokenInput.value = '';
      updateTokenStatus();
      throw new Error('401 Unauthorized — check your admin token');
    }
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(method + ' ' + path + ' → ' + resp.status + ' ' + text);
    }
    if (resp.status === 204) return null;
    return await resp.json();
  }
  function esc(s) { return s === null || s === undefined ? '' : String(s).replace(/[<>&"']/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'})[c]); }

  function renderClients(items) {
    let h = '<div class="btn-row"><button id="btn-new-client">New client</button></div>';
    h += '<table><thead><tr><th>client_id</th><th>name</th><th>auth</th><th>scopes</th><th>pkce</th><th>jwks</th><th></th></tr></thead><tbody>';
    h += items.map(c => '<tr>' +
      '<td><code>' + esc(c.client_id) + '</code></td>' +
      '<td>' + esc(c.display_name) + '</td>' +
      '<td>' + esc(c.token_endpoint_auth_method) + '</td>' +
      '<td>' + esc((c.allowed_scopes || []).join(', ')) + '</td>' +
      '<td>' + (c.require_pkce ? 'yes' : 'no') + '</td>' +
      '<td>' + (c.has_jwks ? 'yes' : 'no') + '</td>' +
      '<td><button class="btn-edit" data-id="' + esc(c.client_id) + '">Edit</button> ' +
      '<button class="btn-del btn-danger" data-id="' + esc(c.client_id) + '">Delete</button></td>' +
      '</tr>').join('');
    h += '</tbody></table>';
    return h;
  }

  function clientForm(c, isEdit) {
    const scopes = (c.allowed_scopes || []).join('\n');
    const redirects = (c.redirect_uris || []).join('\n');
    const postLogout = (c.post_logout_redirect_uris || []).join('\n');
    const props = c.properties ? JSON.stringify(c.properties, null, 2) : '';
    const method = c.token_endpoint_auth_method || 'none';
    return '<h2>' + (isEdit ? 'Edit client' : 'New client') + '</h2>' +
      '<form id="client-form">' +
      '<div class="form-grid">' +
      '<label for="f-client_id">client_id</label>' +
      '<div><input id="f-client_id" value="' + esc(c.client_id || '') + '"' + (isEdit ? ' readonly' : '') + ' required></div>' +
      '<label for="f-display_name">display_name</label>' +
      '<div><input id="f-display_name" value="' + esc(c.display_name || '') + '"></div>' +
      '<label for="f-redirect_uris">redirect_uris</label>' +
      '<div><textarea id="f-redirect_uris" placeholder="one per line">' + esc(redirects) + '</textarea><span class="hint">One URI per line</span></div>' +
      '<label for="f-post_logout_redirect_uris">post_logout_redirect_uris</label>' +
      '<div><textarea id="f-post_logout_redirect_uris" placeholder="one per line">' + esc(postLogout) + '</textarea></div>' +
      '<label for="f-allowed_scopes">allowed_scopes</label>' +
      '<div><textarea id="f-allowed_scopes" placeholder="one per line">' + esc(scopes) + '</textarea></div>' +
      '<label for="f-auth_method">token_endpoint_auth_method</label>' +
      '<div><select id="f-auth_method"><option value="none"' + (method === 'none' ? ' selected' : '') + '>none</option><option value="private_key_jwt"' + (method === 'private_key_jwt' ? ' selected' : '') + '>private_key_jwt</option></select></div>' +
      '<label for="f-jwks_json">jwks_json</label>' +
      '<div><textarea id="f-jwks_json" placeholder=\'{"keys":[...]}\'' + (method !== 'private_key_jwt' ? ' style="display:none"' : '') + '>' + esc(c.jwks_json || '') + '</textarea><span class="hint">Required for private_key_jwt</span></div>' +
      '<label for="f-require_pkce">require_pkce</label>' +
      '<div><input id="f-require_pkce" type="checkbox"' + (c.require_pkce ? ' checked' : '') + '></div>' +
      '<label for="f-allow_refresh_tokens">allow_refresh_tokens</label>' +
      '<div><input id="f-allow_refresh_tokens" type="checkbox"' + (c.allow_refresh_tokens ? ' checked' : '') + '></div>' +
      '<label for="f-allow_client_credentials">allow_client_credentials</label>' +
      '<div><input id="f-allow_client_credentials" type="checkbox"' + (c.allow_client_credentials ? ' checked' : '') + '></div>' +
      '<label for="f-access_lt">access_token_lifetime (s)</label>' +
      '<div><input id="f-access_lt" type="number" min="0" value="' + (c.access_token_lifetime_seconds || '') + '"><span class="hint">0 = server default</span></div>' +
      '<label for="f-refresh_lt">refresh_token_lifetime (s)</label>' +
      '<div><input id="f-refresh_lt" type="number" min="0" value="' + (c.refresh_token_lifetime_seconds || '') + '"></div>' +
      '<label for="f-refresh_abs_lt">refresh_token_abs_lifetime (s)</label>' +
      '<div><input id="f-refresh_abs_lt" type="number" min="0" value="' + (c.refresh_token_absolute_lifetime_seconds || '') + '"></div>' +
      '<label for="f-properties">properties</label>' +
      '<div><textarea id="f-properties" placeholder=\'{"key":"value"}\'' + '>' + esc(props) + '</textarea><span class="hint">JSON object</span></div>' +
      '</div>' +
      '<div class="btn-row"><button type="submit">' + (isEdit ? 'Update' : 'Create') + '</button> <button type="button" id="btn-cancel">Cancel</button></div>' +
      '<div id="form-error"></div>' +
      '</form>';
  }

  function splitLines(s) { return (s || '').split(/[\n,]+/).map(x => x.trim()).filter(Boolean); }
  function readForm() {
    let props = {};
    const propsRaw = document.getElementById('f-properties').value.trim();
    if (propsRaw) { try { props = JSON.parse(propsRaw); } catch(e) { throw new Error('properties: ' + e.message); } }
    return {
      client_id: document.getElementById('f-client_id').value.trim(),
      display_name: document.getElementById('f-display_name').value.trim(),
      redirect_uris: splitLines(document.getElementById('f-redirect_uris').value),
      post_logout_redirect_uris: splitLines(document.getElementById('f-post_logout_redirect_uris').value),
      allowed_scopes: splitLines(document.getElementById('f-allowed_scopes').value),
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
      document.getElementById('f-jwks_json').style.display = this.value === 'private_key_jwt' ? '' : 'none';
    });
    document.getElementById('btn-cancel').addEventListener('click', () => showClients());
    document.getElementById('client-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errDiv = document.getElementById('form-error');
      errDiv.textContent = '';
      try {
        const body = readForm();
        if (isEdit) {
          await call('PUT', '/admin/api/clients/' + encodeURIComponent(body.client_id), body);
        } else {
          await call('POST', '/admin/api/clients', body);
        }
        showClients();
      } catch (err) {
        errDiv.innerHTML = '<p class="err">' + esc(err.message) + '</p>';
      }
    });
  }

  async function showClients() {
    const out = document.getElementById('content');
    out.innerHTML = '<p class="muted">loading…</p>';
    try {
      const r = await call('GET', '/admin/api/clients');
      out.innerHTML = renderClients(r.items || []);
      document.getElementById('btn-new-client').addEventListener('click', () => {
        out.innerHTML = clientForm({require_pkce: true}, false);
        bindClientForm(false);
      });
      out.querySelectorAll('.btn-edit').forEach(btn => {
        btn.addEventListener('click', async () => {
          const id = btn.getAttribute('data-id');
          try {
            const c = await call('GET', '/admin/api/clients/' + encodeURIComponent(id));
            out.innerHTML = clientForm(c, true);
            bindClientForm(true);
          } catch (e) { out.innerHTML = '<p class="err">' + esc(e.message) + '</p>'; }
        });
      });
      out.querySelectorAll('.btn-del').forEach(btn => {
        btn.addEventListener('click', async () => {
          const id = btn.getAttribute('data-id');
          if (!confirm('Delete client "' + id + '"?')) return;
          try {
            await call('DELETE', '/admin/api/clients/' + encodeURIComponent(id));
            showClients();
          } catch (e) { out.innerHTML = '<p class="err">' + esc(e.message) + '</p>'; }
        });
      });
    } catch (e) {
      out.innerHTML = '<p class="err">' + esc(e.message) + '</p>';
    }
  }

  function renderScopes(items) {
    return '<table><thead><tr><th>name</th><th>display</th><th>required</th></tr></thead><tbody>' +
      items.map(s => '<tr><td><code>' + esc(s.name) + '</code></td><td>' + esc(s.display_name) + '</td><td>' + (s.required ? 'yes' : 'no') + '</td></tr>').join('') +
      '</tbody></table>';
  }
  function renderUsers(items) {
    let h = '<div class="btn-row"><button id="btn-new-user">New user</button></div>';
    h += '<table><thead><tr><th>id</th><th>username</th><th>email</th><th>2fa</th><th>lockout</th><th></th></tr></thead><tbody>';
    h += items.map(u => '<tr>' +
      '<td><code>' + esc(u.id) + '</code></td>' +
      '<td>' + esc(u.username) + '</td>' +
      '<td>' + esc(u.email) + (u.email_confirmed ? ' ✓' : '') + '</td>' +
      '<td>' + (u.two_factor_enabled ? 'yes' : 'no') + '</td>' +
      '<td>' + (u.lockout_enabled ? (u.lockout_end ? esc(u.lockout_end) : 'enabled') : 'no') + '</td>' +
      '<td><button class="btn-edit-user" data-id="' + esc(u.id) + '">Edit</button> ' +
      '<button class="btn-del-user btn-danger" data-id="' + esc(u.id) + '">Delete</button></td>' +
      '</tr>').join('');
    h += '</tbody></table>';
    return h;
  }
  function renderRoles(items) {
    let h = '<div class="btn-row"><button id="btn-new-role">New role</button></div>';
    h += '<table><thead><tr><th>id</th><th>name</th><th></th></tr></thead><tbody>';
    h += items.map(r => '<tr>' +
      '<td><code>' + esc(r.id) + '</code></td>' +
      '<td>' + esc(r.name) + '</td>' +
      '<td><button class="btn-del-role btn-danger" data-id="' + esc(r.id) + '">Delete</button></td>' +
      '</tr>').join('');
    h += '</tbody></table>';
    return h;
  }
  function renderSessions(items) {
    return '<table><thead><tr><th>id</th><th>user_id</th><th>expires</th><th>revoked</th></tr></thead><tbody>' +
      items.map(s => '<tr><td><code>' + esc(s.id) + '</code></td><td>' + esc(s.user_id) + '</td><td>' + esc(s.expires_at) + '</td><td>' + (s.revoked_at ? 'yes' : 'no') + '</td></tr>').join('') +
      '</tbody></table>';
  }
  function renderTokens(items) {
    return '<table><thead><tr><th>id</th><th>client</th><th>user</th><th>scope</th><th>expires</th></tr></thead><tbody>' +
      items.map(t => '<tr><td><code>' + esc(t.id) + '</code></td><td>' + esc(t.client_id) + '</td><td>' + esc(t.user_id) + '</td><td>' + esc(t.scope) + '</td><td>' + esc(t.expires_at) + '</td></tr>').join('') +
      '</tbody></table>';
  }
  function renderKeys(items) {
    return '<table><thead><tr><th>kid</th><th>alg</th><th>active</th><th>public_pem</th></tr></thead><tbody>' +
      items.map(k => '<tr><td><code>' + esc(k.kid) + '</code></td><td>' + esc(k.alg) + '</td><td>' + (k.is_active ? 'yes' : 'no') + '</td><td><pre style="white-space:pre-wrap;margin:0">' + esc(k.public_pem) + '</pre></td></tr>').join('') +
      '</tbody></table>';
  }
  function renderAudit(items) {
    return '<table><thead><tr><th>timestamp</th><th>action</th><th>actor</th><th>target</th></tr></thead><tbody>' +
      items.map(l => '<tr><td>' + esc(l.timestamp) + '</td><td>' + esc(l.action) + '</td><td>' + esc(l.actor_user_id) + '</td><td>' + esc(l.target_type) + ':' + esc(l.target_id) + '</td></tr>').join('') +
      '</tbody></table>';
  }

  document.querySelectorAll('nav button').forEach(btn => {
    btn.addEventListener('click', async () => {
      const tab = btn.getAttribute('data-tab');
      const out = document.getElementById('content');
      out.innerHTML = '<p class="muted">loading…</p>';
      try {
        if (tab === 'clients') { showClients(); return; }
        if (tab === 'users') { showUsers(); return; }
        if (tab === 'roles') { showRoles(); return; }
        const r = await call('GET', '/admin/api/' + tab);
        const items = r.items || [];
        if (tab === 'scopes') out.innerHTML = renderScopes(items);
        else if (tab === 'sessions') out.innerHTML = renderSessions(items);
        else if (tab === 'refresh-tokens') out.innerHTML = renderTokens(items);
        else if (tab === 'keys') out.innerHTML = renderKeys(items);
        else if (tab === 'audit') out.innerHTML = renderAudit(items);
      } catch (e) {
        out.innerHTML = '<p class="err">' + esc(e.message) + '</p>';
      }
    });
  });

  async function showUsers() {
    const out = document.getElementById('content');
    out.innerHTML = '<p class="muted">loading…</p>';
    try {
      const r = await call('GET', '/admin/api/users');
      out.innerHTML = renderUsers(r.items || []);
      document.getElementById('btn-new-user').addEventListener('click', () => showUserForm(null));
      out.querySelectorAll('.btn-edit-user').forEach(btn => {
        btn.addEventListener('click', async () => {
          const id = btn.getAttribute('data-id');
          try {
            const u = await call('GET', '/admin/api/users/' + encodeURIComponent(id));
            showUserForm(u);
          } catch (e) { out.innerHTML = '<p class="err">' + esc(e.message) + '</p>'; }
        });
      });
      out.querySelectorAll('.btn-del-user').forEach(btn => {
        btn.addEventListener('click', async () => {
          const id = btn.getAttribute('data-id');
          if (!confirm('Delete user "' + id + '"?')) return;
          try {
            await call('DELETE', '/admin/api/users/' + encodeURIComponent(id));
            showUsers();
          } catch (e) { out.innerHTML = '<p class="err">' + esc(e.message) + '</p>'; }
        });
      });
    } catch (e) {
      out.innerHTML = '<p class="err">' + esc(e.message) + '</p>';
    }
  }

  function showUserForm(u) {
    const isEdit = !!u;
    const out = document.getElementById('content');
    out.innerHTML = '<h2>' + (isEdit ? 'Edit user' : 'New user') + '</h2>' +
      '<form id="user-form"><div class="form-grid">' +
      '<label>id</label><div><input id="f-id" value="' + esc(u ? u.id : '') + '"' + (isEdit ? ' readonly' : '') + ' required></div>' +
      '<label>username</label><div><input id="f-username" value="' + esc(u ? u.username : '') + '"></div>' +
      '<label>email</label><div><input id="f-email" value="' + esc(u ? u.email : '') + '"></div>' +
      '<label>email_confirmed</label><div><input id="f-email_confirmed" type="checkbox"' + (u && u.email_confirmed ? ' checked' : '') + '></div>' +
      '<label>phone_number</label><div><input id="f-phone_number" value="' + esc(u ? u.phone_number : '') + '"></div>' +
      '<label>phone_number_confirmed</label><div><input id="f-phone_number_confirmed" type="checkbox"' + (u && u.phone_number_confirmed ? ' checked' : '') + '></div>' +
      '<label>two_factor_enabled</label><div><input id="f-two_factor_enabled" type="checkbox"' + (u && u.two_factor_enabled ? ' checked' : '') + '></div>' +
      '<label>lockout_enabled</label><div><input id="f-lockout_enabled" type="checkbox"' + (u && u.lockout_enabled ? ' checked' : '') + '></div>' +
      (isEdit ? '' : '<label>password</label><div><input id="f-password" type="password" required></div>') +
      '</div><div class="btn-row"><button type="submit">' + (isEdit ? 'Update' : 'Create') + '</button> <button type="button" id="btn-cancel">Cancel</button></div>' +
      '<div id="form-error"></div></form>';
    document.getElementById('btn-cancel').addEventListener('click', () => showUsers());
    document.getElementById('user-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errDiv = document.getElementById('form-error');
      errDiv.textContent = '';
      try {
        if (isEdit) {
          await call('PUT', '/admin/api/users/' + encodeURIComponent(u.id), {
            username: document.getElementById('f-username').value,
            email: document.getElementById('f-email').value,
            email_confirmed: document.getElementById('f-email_confirmed').checked,
            phone_number: document.getElementById('f-phone_number').value,
            phone_number_confirmed: document.getElementById('f-phone_number_confirmed').checked,
            two_factor_enabled: document.getElementById('f-two_factor_enabled').checked,
            lockout_enabled: document.getElementById('f-lockout_enabled').checked
          });
        } else {
          await call('POST', '/admin/api/users', {
            id: document.getElementById('f-id').value,
            username: document.getElementById('f-username').value,
            email: document.getElementById('f-email').value,
            password: document.getElementById('f-password').value
          });
        }
        showUsers();
      } catch (err) {
        errDiv.innerHTML = '<p class="err">' + esc(err.message) + '</p>';
      }
    });
  }

  async function showRoles() {
    const out = document.getElementById('content');
    out.innerHTML = '<p class="muted">loading…</p>';
    try {
      const r = await call('GET', '/admin/api/roles');
      out.innerHTML = renderRoles(r.items || []);
      document.getElementById('btn-new-role').addEventListener('click', () => showRoleForm());
      out.querySelectorAll('.btn-del-role').forEach(btn => {
        btn.addEventListener('click', async () => {
          const id = btn.getAttribute('data-id');
          if (!confirm('Delete role "' + id + '"?')) return;
          try {
            await call('DELETE', '/admin/api/roles/' + encodeURIComponent(id));
            showRoles();
          } catch (e) { out.innerHTML = '<p class="err">' + esc(e.message) + '</p>'; }
        });
      });
    } catch (e) {
      out.innerHTML = '<p class="err">' + esc(e.message) + '</p>';
    }
  }

  function showRoleForm() {
    const out = document.getElementById('content');
    out.innerHTML = '<h2>New role</h2>' +
      '<form id="role-form"><div class="form-grid">' +
      '<label>id</label><div><input id="f-role-id" required></div>' +
      '<label>name</label><div><input id="f-role-name" required></div>' +
      '</div><div class="btn-row"><button type="submit">Create</button> <button type="button" id="btn-cancel">Cancel</button></div>' +
      '<div id="form-error"></div></form>';
    document.getElementById('btn-cancel').addEventListener('click', () => showRoles());
    document.getElementById('role-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errDiv = document.getElementById('form-error');
      errDiv.textContent = '';
      try {
        await call('POST', '/admin/api/roles', {
          id: document.getElementById('f-role-id').value,
          name: document.getElementById('f-role-name').value
        });
        showRoles();
      } catch (err) {
        errDiv.innerHTML = '<p class="err">' + esc(err.message) + '</p>';
      }
    });
  }
})();
</script>
</body>
</html>`

// ServeIndex renders the SPA shell with the CSRF token injected. The
// page is the same regardless of the auth state (anonymous or
// token-bearer) — the JS does not need the token, only the API
// requests do.
func (u *UI) ServeIndex(w http.ResponseWriter, r *http.Request) {
	if u.Template == nil {
		http.Error(w, "admin template not configured", http.StatusInternalServerError)
		return
	}
	// gorilla/csrf injects the token into the request context under
	// the csrf.TemplateField key. The csrf middleware also sets
	// the cookie on the response; we just need to surface the
	// token value as a meta tag so the SPA can echo it in the
	// X-CSRF-Token header on mutating calls.
	csrfToken, _ := csrfFromContext(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := u.Template.Execute(w, map[string]any{"CSRFToken": csrfToken}); err != nil {
		if u.Logger != nil {
			u.Logger.Error("admin index render", "err", err)
		}
	}
}
