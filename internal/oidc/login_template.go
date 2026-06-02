package oidc

// LoginTemplate returns the minimal login form HTML. Exported so the
// composition root in cmd/authserver and the integration tests can
// share the same form definition.
func LoginTemplate() string { return loginHTML }

// loginHTML is the minimal login form. The CSRF token is rendered as a
// hidden input; returnUrl is echoed the same way. Kept inline (not a
// separate file) so test setups do not have to juggle embedded
// filesystems.
const loginHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign in</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body { font-family: system-ui, sans-serif; max-width: 24rem; margin: 4rem auto; padding: 0 1rem; }
  h1 { font-size: 1.25rem; }
  .err { color: #b00020; margin: 0.5rem 0; }
  label { display: block; margin: 0.75rem 0 0.25rem; }
  input[type=text], input[type=password] { width: 100%; padding: 0.5rem; box-sizing: border-box; }
  button { margin-top: 1rem; padding: 0.5rem 1rem; }
  .register-link { display: block; margin-top: 1.5rem; text-align: center; font-size: 0.875rem; color: #0056b3; text-decoration: none; }
  .register-link:hover { text-decoration: underline; }
</style>
</head>
<body>
<h1>Sign in</h1>
{{ if .Error }}<p class="err">{{ .ErrorLabel }}</p>{{ end }}
<form method="post" action="{{ .Action }}">
  <input type="hidden" name="csrf_token" value="{{ .CSRFToken }}">
  <input type="hidden" name="returnUrl" value="{{ .ReturnURL }}">
  <label for="username">Username</label>
  <input id="username" name="username" type="text" autocomplete="username" required autofocus>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Sign in</button>
</form>
<a class="register-link" href="{{ .RegisterPath }}">Don't have an account? Register</a>
</body>
</html>`
