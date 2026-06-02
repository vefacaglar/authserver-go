package oidc

// This file holds the shared building blocks for the auth pages (login,
// register). Each page is composed from a common base layout, a shared
// stylesheet, and a reusable error banner, plus a page-specific "content"
// block. They are concatenated into one string per page and parsed as a
// single html/template set, so editing the chrome (head, card shell,
// styles) happens in exactly one place.
//
// Kept as Go string constants rather than embedded files so test setups do
// not have to juggle embedded filesystems — they parse the same string the
// composition root does.

// authPage stitches a page-specific content block together with the shared
// base layout, styles, and error banner into a single parseable template.
// The root body (outside every {{define}}) is the lone {{template "base"}}
// invocation, so Execute on the named root renders the full page.
func authPage(content string) string {
	return baseLayout + sharedStyles + errorBanner + content + `{{ template "base" . }}`
}

// baseLayout is the HTML shell shared by every auth page. The page supplies
// "heading" (the card title) and "content" (the form + footer); everything
// else — doctype, head, centered card, error banner slot — lives here.
const baseLayout = `{{ define "base" }}<!doctype html>
<html lang="en" class="h-full bg-[#121212]">
<head>
<meta charset="utf-8">
<title>{{ template "heading" . }}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://cdn.tailwindcss.com"></script>
{{ template "styles" . }}
</head>
<body class="h-full flex min-h-full flex-col justify-center py-12 px-4 sm:px-6 lg:px-8 bg-[#121212] text-zinc-400 font-mono antialiased">
  
  <div class="sm:mx-auto sm:w-full sm:max-w-[400px]">
    <div class="bg-[#1a1a1a] p-8 border border-zinc-800/60 shadow-lg rounded-none">
      
      <!-- Minimalist heading inside the box -->
      <div class="mb-6">
        <h1 class="text-lg font-bold text-zinc-300 tracking-tight lowercase">
          {{ template "heading" . }}
        </h1>
      </div>

      {{ template "errorBanner" . }}
      {{ template "content" . }}

    </div>
  </div>

</body>
</html>{{ end }}`

// sharedStyles loads the Inter font and defines semantic component classes
// via Tailwind's Play CDN (<style type="text/tailwindcss"> + @apply). The
// long utility strings live here once; markup just references .auth-input,
// .auth-label, .auth-btn, .auth-link.
const sharedStyles = `{{ define "styles" }}<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap');
  body { font-family: 'JetBrains Mono', ui-monospace, monospace; }
  input:-webkit-autofill,
  input:-webkit-autofill:hover,
  input:-webkit-autofill:focus {
    -webkit-text-fill-color: #09090b !important;
    -webkit-box-shadow: 0 0 0px 1000px #cbd5e1 inset !important;
    transition: background-color 5000s ease-in-out 0s;
  }
</style>
<style type="text/tailwindcss">
  @layer components {
    .auth-label { @apply block text-xs text-zinc-500 lowercase tracking-wide mb-2; }
    .auth-input { @apply block w-full rounded-none border-0 py-3 px-4 bg-[#cbd5e1] text-zinc-950 placeholder:text-zinc-500 focus:bg-[#cbd5e1] focus:ring-0 sm:text-sm font-mono outline-none; }
    .auth-btn { @apply flex w-full justify-center rounded-none bg-zinc-300 px-3 py-3 text-sm font-bold text-zinc-950 shadow-sm hover:bg-zinc-400 transition-colors lowercase tracking-wide font-mono; }
    .auth-link { @apply text-zinc-500 hover:text-zinc-300 transition-colors underline decoration-1 underline-offset-4 font-mono text-xs lowercase; }
  }
</style>{{ end }}`

// errorBanner renders the red alert box when .Error is set. Shared so both
// pages surface validation/server errors identically.
const errorBanner = `{{ define "errorBanner" }}{{ if .Error }}
    <div class="rounded-none bg-red-950/20 px-4 py-3 mb-6 border-l-2 border-red-500 text-red-400 font-mono text-xs lowercase">
      error: {{ .ErrorLabel }}
    </div>
    {{ end }}{{ end }}`
