package oidc

// RegisterTemplate returns the register page HTML. Like the login page it
// is composed from the shared base layout (templates.go) plus the page's
// own "heading" + "content" blocks.
func RegisterTemplate() string { return authPage(registerContent) }

// registerContent is everything specific to the sign-up page.
const registerContent = `{{ define "heading" }}Create an Account{{ end }}
{{ define "content" }}
    <form class="space-y-6" method="post" action="{{ .Action }}{{ if .ReturnURL }}?returnUrl={{ .ReturnURL }}{{ end }}">
      <input type="hidden" name="csrf_token" value="{{ .CSRFToken }}">

      <div>
        <label for="username" class="auth-label">Username</label>
        <div class="mt-2">
          <input id="username" name="username" type="text" autocomplete="username" required autofocus class="auth-input">
        </div>
      </div>

      <div>
        <label for="email" class="auth-label">Email</label>
        <div class="mt-2">
          <input id="email" name="email" type="email" autocomplete="email" required class="auth-input">
        </div>
      </div>

      <div>
        <label for="password" class="auth-label">Password</label>
        <div class="mt-2">
          <input id="password" name="password" type="password" autocomplete="new-password" required minlength="6" class="auth-input">
        </div>
      </div>

      <div>
        <label for="password_confirm" class="auth-label">Confirm Password</label>
        <div class="mt-2">
          <input id="password_confirm" name="password_confirm" type="password" autocomplete="new-password" required minlength="6" class="auth-input">
        </div>
      </div>

      <div>
        <button type="submit" class="auth-btn">Register</button>
      </div>
    </form>

    <p class="mt-10 text-center text-sm text-zinc-500">
      Already have an account?
      <a href="{{ .LoginPath }}" class="auth-link">Sign in</a>
    </p>
{{ end }}`
