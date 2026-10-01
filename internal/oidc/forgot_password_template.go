package oidc

// ForgotPasswordTemplate returns the forgot-password page HTML.
func ForgotPasswordTemplate() string { return authPage(forgotContent) }

// The confirmation text is deliberately identical for every identifier;
// see ForgotPasswordHandler.
const forgotContent = `{{ define "heading" }}forgot password{{ end }}
{{ define "content" }}
    {{ if .Sent }}
    <div class="rounded-none bg-emerald-950/20 px-4 py-3 mb-6 border-l-2 border-emerald-500 text-emerald-400 font-mono text-xs lowercase">
      if an account matches, we sent a password reset link to its email address. the link expires soon.
    </div>
    {{ end }}
    <form class="space-y-6" method="post" action="{{ .Action }}">
      <input type="hidden" name="csrf_token" value="{{ .CSRFToken }}">
      <div>
        <label for="identifier" class="auth-label">username or email</label>
        <input id="identifier" name="identifier" type="text" autocomplete="username" required autofocus class="auth-input">
      </div>
      <div>
        <button type="submit" class="auth-btn">send reset link</button>
      </div>
    </form>

    <p class="mt-8 text-xs text-zinc-500 font-mono lowercase">
      remembered it?
      <a href="{{ .LoginPath }}" class="auth-link ml-1">sign in</a>
    </p>
{{ end }}`
