package oidc

// HomeTemplate returns the signed-in home page HTML. Exported so the
// composition root and the integration tests share one definition.
func HomeTemplate() string { return appPage(homeContent) }

// homeContent shows the account summary and the recent sign-in history.
// All values are rendered through html/template, so user-controlled
// strings (name, user agent) are escaped.
const homeContent = `{{ define "heading" }}home{{ end }}
{{ define "nav" }}<a href="{{ .LogoutPath }}" class="auth-link">sign out</a>{{ end }}
{{ define "content" }}
    <section>
      <h1 class="text-lg font-bold text-zinc-300 tracking-tight lowercase">
        welcome{{ if .Name }}, {{ .Name }}{{ else }}, {{ .Username }}{{ end }}
      </h1>
    </section>

    <section class="bg-[#1a1a1a] border border-zinc-800/60 p-6">
      <h2 class="text-xs text-zinc-500 lowercase tracking-wide mb-4">profile</h2>
      <dl class="grid grid-cols-[8rem_1fr] gap-y-3 text-sm">
        <dt class="text-zinc-500 lowercase">username</dt><dd class="text-zinc-300 break-all">{{ .Username }}</dd>
        <dt class="text-zinc-500 lowercase">name</dt><dd class="text-zinc-300 break-all">{{ if .Name }}{{ .Name }}{{ else }}&mdash;{{ end }}</dd>
        <dt class="text-zinc-500 lowercase">email</dt><dd class="text-zinc-300 break-all">{{ if .Email }}{{ .Email }}{{ else }}&mdash;{{ end }}</dd>
      </dl>
    </section>

    <section class="bg-[#1a1a1a] border border-zinc-800/60 p-6">
      <h2 class="text-xs text-zinc-500 lowercase tracking-wide mb-4">recent sign-ins</h2>
      {{ if .Logins }}
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead>
            <tr class="text-xs text-zinc-500 lowercase">
              <th class="pb-2 pr-4 font-normal">when</th>
              <th class="pb-2 pr-4 font-normal">device</th>
              <th class="pb-2 font-normal">ip address</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-zinc-800/60">
            {{ range .Logins }}
            <tr>
              <td class="py-2 pr-4 whitespace-nowrap text-zinc-300">{{ .When }}{{ if .Current }} <span class="ml-2 text-xs text-zinc-500 lowercase">this sign-in</span>{{ end }}</td>
              <td class="py-2 pr-4 text-zinc-300">{{ .Device }}</td>
              <td class="py-2 text-zinc-300 break-all">{{ .IP }}</td>
            </tr>
            {{ end }}
          </tbody>
        </table>
      </div>
      {{ else }}
      <p class="text-sm text-zinc-500 lowercase">no sign-ins recorded yet.</p>
      {{ end }}
    </section>
{{ end }}`
