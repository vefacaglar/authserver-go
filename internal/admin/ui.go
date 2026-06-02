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
  input { padding: 0.3rem 0.5rem; }
</style>
</head>
<body>
<h1>authserver admin</h1>
<nav>
  <button data-tab="clients">Clients</button>
  <button data-tab="scopes">Scopes</button>
  <button data-tab="sessions">Sessions</button>
  <button data-tab="refresh-tokens">Refresh tokens</button>
  <button data-tab="keys">Signing keys</button>
  <button data-tab="audit">Audit</button>
</nav>
<div id="content"><p class="muted">Pick a tab to begin.</p></div>

<script>
(() => {
  const csrf = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
  async function call(method, path, body) {
    const headers = {'X-CSRF-Token': csrf};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const resp = await fetch(path, {method, headers, body: body !== undefined ? JSON.stringify(body) : undefined});
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(method + ' ' + path + ' → ' + resp.status + ' ' + text);
    }
    if (resp.status === 204) return null;
    return await resp.json();
  }
  function esc(s) { return s === null || s === undefined ? '' : String(s).replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'})[c]); }

  function renderClients(items) {
    return '<table><thead><tr><th>client_id</th><th>name</th><th>auth</th><th>scopes</th><th>jti_required</th></tr></thead><tbody>' +
      items.map(c => '<tr><td><code>' + esc(c.client_id) + '</code></td><td>' + esc(c.display_name) + '</td><td>' + esc(c.token_endpoint_auth_method) + '</td><td>' + esc((c.allowed_scopes || []).join(',')) + '</td><td>' + (c.require_pkce ? 'yes' : 'no') + '</td></tr>').join('') +
      '</tbody></table>';
  }
  function renderScopes(items) {
    return '<table><thead><tr><th>name</th><th>display</th><th>required</th></tr></thead><tbody>' +
      items.map(s => '<tr><td><code>' + esc(s.name) + '</code></td><td>' + esc(s.display_name) + '</td><td>' + (s.required ? 'yes' : 'no') + '</td></tr>').join('') +
      '</tbody></table>';
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
        const r = await call('GET', '/admin/api/' + tab);
        const items = r.items || [];
        if (tab === 'clients') out.innerHTML = renderClients(items);
        else if (tab === 'scopes') out.innerHTML = renderScopes(items);
        else if (tab === 'sessions') out.innerHTML = renderSessions(items);
        else if (tab === 'refresh-tokens') out.innerHTML = renderTokens(items);
        else if (tab === 'keys') out.innerHTML = renderKeys(items);
        else if (tab === 'audit') out.innerHTML = renderAudit(items);
      } catch (e) {
        out.innerHTML = '<p class="err">' + esc(e.message) + '</p>';
      }
    });
  });
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
