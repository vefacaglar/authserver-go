package oidc

// RegisterTemplate returns the register page HTML. Like the login page it
// is composed from the shared base layout (templates.go) plus the page's
// own "heading" + "content" blocks.
func RegisterTemplate() string { return authPage(registerContent) }

// registerContent is everything specific to the sign-up page.
const registerContent = `{{ define "heading" }}create account{{ end }}
{{ define "content" }}
    <form class="space-y-6" method="post" action="{{ .Action }}{{ if .ReturnURL }}?returnUrl={{ .ReturnURL }}{{ end }}" onsubmit="var btn = this.querySelector('button'); btn.innerText = 'registering...'; btn.style.pointerEvents = 'none'; btn.style.opacity = '0.75';">
      <input type="hidden" name="csrf_token" value="{{ .CSRFToken }}">

      <div>
        <label for="username" class="auth-label">username</label>
        <input id="username" name="username" type="text" autocomplete="username" required autofocus class="auth-input">
      </div>

      <div>
        <label for="email" class="auth-label">email</label>
        <input id="email" name="email" type="email" autocomplete="email" required class="auth-input">
      </div>

      <div>
        <label for="password" class="auth-label">password</label>
        <input id="password" name="password" type="password" autocomplete="new-password" required minlength="6" class="auth-input">
      </div>

      <div>
        <label for="password_confirm" class="auth-label">confirm password</label>
        <input id="password_confirm" name="password_confirm" type="password" autocomplete="new-password" required minlength="6" class="auth-input">
      </div>

      <div>
        <button type="submit" class="auth-btn">register</button>
      </div>
    </form>

    <p class="mt-8 text-xs text-zinc-500 font-mono lowercase">
      already have an account?
      <a href="{{ .LoginPath }}" class="auth-link ml-1">sign in</a>
    </p>
{{ end }}`
