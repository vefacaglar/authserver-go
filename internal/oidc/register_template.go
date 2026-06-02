package oidc

// RegisterTemplate returns the minimal register form HTML.
func RegisterTemplate() string { return registerHTML }

const registerHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Register</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body { font-family: system-ui, sans-serif; max-width: 24rem; margin: 4rem auto; padding: 0 1rem; }
  h1 { font-size: 1.25rem; }
  .err { color: #b00020; margin: 0.5rem 0; }
  label { display: block; margin: 0.75rem 0 0.25rem; }
  input[type=text], input[type=password], input[type=email] { width: 100%; padding: 0.5rem; box-sizing: border-box; }
  button { margin-top: 1rem; padding: 0.5rem 1rem; }
  .login-link { display: block; margin-top: 1.5rem; text-align: center; font-size: 0.875rem; color: #0056b3; text-decoration: none; }
  .login-link:hover { text-decoration: underline; }
</style>
</head>
<body>
<h1>Create an Account</h1>
{{ if .Error }}<p class="err">{{ .ErrorLabel }}</p>{{ end }}
<form method="post" action="{{ .Action }}">
  <input type="hidden" name="csrf_token" value="{{ .CSRFToken }}">
  <label for="username">Username</label>
  <input id="username" name="username" type="text" autocomplete="username" required autofocus>
  
  <label for="email">Email</label>
  <input id="email" name="email" type="email" autocomplete="email" required>
  
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="new-password" required minlength="6">
  
  <label for="password_confirm">Confirm Password</label>
  <input id="password_confirm" name="password_confirm" type="password" autocomplete="new-password" required minlength="6">
  
  <button type="submit">Register</button>
</form>
<a class="login-link" href="{{ .LoginPath }}">Already have an account? Sign in</a>
</body>
</html>`
