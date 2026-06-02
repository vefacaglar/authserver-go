package oidc

// LoginTemplate returns the login page HTML. Exported so the composition
// root in cmd/authserver and the integration tests share one definition.
// The page is just its "heading" + "content" blocks; the head, card shell,
// styles, and error banner come from the shared base layout (templates.go).
func LoginTemplate() string { return authPage(loginContent) }

// loginContent is everything specific to the sign-in page: the title and
// the form. The CSRF token and returnUrl are rendered as hidden inputs.
const loginContent = `{{ define "heading" }}Sign in to your account{{ end }}
{{ define "content" }}
    <form class="space-y-6" method="post" action="{{ .Action }}">
      <input type="hidden" name="csrf_token" value="{{ .CSRFToken }}">
      <input type="hidden" name="returnUrl" value="{{ .ReturnURL }}">

      <div>
        <label for="username" class="auth-label">Username</label>
        <div class="mt-2">
          <input id="username" name="username" type="text" autocomplete="username" required autofocus class="auth-input">
        </div>
      </div>

      <div>
        <label for="password" class="auth-label">Password</label>
        <div class="mt-2">
          <input id="password" name="password" type="password" autocomplete="current-password" required class="auth-input">
        </div>
      </div>

      <div>
        <button type="submit" class="auth-btn">Sign in</button>
      </div>
    </form>

    <p class="mt-10 text-center text-sm text-zinc-500">
      Don't have an account?
      <a href="{{ .RegisterPath }}" class="auth-link">Register</a>
    </p>
{{ end }}`
