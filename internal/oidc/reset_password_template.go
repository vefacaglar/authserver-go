package oidc

// ResetPasswordTemplate returns the reset-password page HTML.
func ResetPasswordTemplate() string { return authPage(resetContent) }

// resetContent shows the new-password form for a valid link and, for any
// invalid one (missing, wrong, used, expired), a single generic message.
const resetContent = `{{ define "heading" }}reset password{{ end }}
{{ define "content" }}
    {{ if .TokenValid }}
    <form class="space-y-6" method="post" action="{{ .Action }}">
      <input type="hidden" name="csrf_token" value="{{ .CSRFToken }}">
      <input type="hidden" name="token" value="{{ .Token }}">
      <div>
        <label for="new_password" class="auth-label">new password</label>
        <input id="new_password" name="new_password" type="password" autocomplete="new-password" required autofocus minlength="8" maxlength="72" class="auth-input">
      </div>
      <div>
        <label for="new_password_confirm" class="auth-label">confirm new password</label>
        <input id="new_password_confirm" name="new_password_confirm" type="password" autocomplete="new-password" required minlength="8" maxlength="72" class="auth-input">
      </div>
      <p class="text-xs text-zinc-500 lowercase">8-72 characters. all your sessions will be signed out.</p>
      <div>
        <button type="submit" class="auth-btn">set new password</button>
      </div>
    </form>
    {{ else }}
    <p class="text-xs text-zinc-500 font-mono lowercase">
      <a href="{{ .ForgotPath }}" class="auth-link">request a new link</a>
      <span class="mx-2">/</span>
      <a href="{{ .LoginPath }}" class="auth-link">sign in</a>
    </p>
    {{ end }}
{{ end }}`
