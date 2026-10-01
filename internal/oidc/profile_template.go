package oidc

// ProfileTemplate returns the profile page HTML. Exported so the
// composition root and the integration tests share one definition.
func ProfileTemplate() string { return appPage(profileContent) }

// profileContent holds the editable name form, the read-only account
// fields and the active-session list with per-session sign-out.
const profileContent = `{{ define "heading" }}my profile{{ end }}
{{ define "content" }}
    <section>
      <h1 class="text-lg font-bold text-zinc-300 tracking-tight lowercase">my profile</h1>
    </section>

    <section class="bg-[#1a1a1a] border border-zinc-800/60 p-6">
      <h2 class="text-xs text-zinc-500 lowercase tracking-wide mb-4">account</h2>
      <form class="space-y-6" method="post" action="{{ .Action }}">
        <input type="hidden" name="csrf_token" value="{{ .CSRFToken }}">
        <div>
          <label for="name" class="auth-label">name</label>
          <input id="name" name="name" type="text" value="{{ .Name }}" maxlength="100" autocomplete="name" required class="auth-input">
        </div>
        <dl class="grid grid-cols-[8rem_1fr] gap-y-3 text-sm">
          <dt class="text-zinc-500 lowercase">username</dt><dd class="text-zinc-300 break-all">{{ .Username }}</dd>
          <dt class="text-zinc-500 lowercase">email</dt><dd class="text-zinc-300 break-all">{{ if .Email }}{{ .Email }}{{ else }}&mdash;{{ end }}</dd>
        </dl>
        <div class="sm:w-40">
          <button type="submit" class="auth-btn">save</button>
        </div>
      </form>
    </section>

    <section class="bg-[#1a1a1a] border border-zinc-800/60 p-6">
      <h2 class="text-xs text-zinc-500 lowercase tracking-wide mb-4">change password</h2>
      <form class="space-y-6" method="post" action="{{ .PasswordAction }}">
        <input type="hidden" name="csrf_token" value="{{ .CSRFToken }}">
        <div>
          <label for="current_password" class="auth-label">current password</label>
          <input id="current_password" name="current_password" type="password" autocomplete="current-password" required class="auth-input">
        </div>
        <div>
          <label for="new_password" class="auth-label">new password</label>
          <input id="new_password" name="new_password" type="password" autocomplete="new-password" required minlength="8" maxlength="72" class="auth-input">
        </div>
        <div>
          <label for="new_password_confirm" class="auth-label">confirm new password</label>
          <input id="new_password_confirm" name="new_password_confirm" type="password" autocomplete="new-password" required minlength="8" maxlength="72" class="auth-input">
        </div>
        <p class="text-xs text-zinc-500 lowercase">8-72 characters. changing your password signs out all your other sessions.</p>
        <div class="sm:w-56">
          <button type="submit" class="auth-btn">change password</button>
        </div>
      </form>
    </section>

    <section class="bg-[#1a1a1a] border border-zinc-800/60 p-6">
      <div class="mb-4 flex items-center justify-between">
        <h2 class="text-xs text-zinc-500 lowercase tracking-wide">active sessions</h2>
        {{ if .HasOtherSessions }}
        <form method="post" action="{{ .RevokeOthersAction }}">
          <input type="hidden" name="csrf_token" value="{{ .CSRFToken }}">
          <button type="submit" class="auth-link">sign out all other sessions</button>
        </form>
        {{ end }}
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead>
            <tr class="text-xs text-zinc-500 lowercase">
              <th class="pb-2 pr-4 font-normal">signed in</th>
              <th class="pb-2 pr-4 font-normal">expires</th>
              <th class="pb-2 font-normal"></th>
            </tr>
          </thead>
          <tbody class="divide-y divide-zinc-800/60">
            {{ range .Sessions }}
            <tr>
              <td class="py-2 pr-4 whitespace-nowrap text-zinc-300">{{ .Created }}</td>
              <td class="py-2 pr-4 whitespace-nowrap text-zinc-300">{{ .Expires }}</td>
              <td class="py-2 text-right">
                {{ if .Current }}
                <span class="text-xs text-zinc-500 lowercase">this device</span>
                {{ else }}
                <form method="post" action="{{ $.RevokeAction }}">
                  <input type="hidden" name="csrf_token" value="{{ $.CSRFToken }}">
                  <input type="hidden" name="session_id" value="{{ .ID }}">
                  <button type="submit" class="auth-link">sign out</button>
                </form>
                {{ end }}
              </td>
            </tr>
            {{ end }}
          </tbody>
        </table>
      </div>
    </section>
{{ end }}`
