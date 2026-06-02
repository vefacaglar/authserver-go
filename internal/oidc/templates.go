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
<html lang="en" class="h-full bg-zinc-950">
<head>
<meta charset="utf-8">
<title>{{ template "heading" . }}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://cdn.tailwindcss.com"></script>
{{ template "styles" . }}
</head>
<body class="h-full flex min-h-full flex-col justify-center py-12 sm:px-6 lg:px-8">
<div class="sm:mx-auto sm:w-full sm:max-w-md">
  <h2 class="mt-6 text-center text-2xl font-semibold leading-9 tracking-tight text-zinc-100">{{ template "heading" . }}</h2>
</div>

<div class="mt-10 sm:mx-auto sm:w-full sm:max-w-[480px]">
  <div class="bg-zinc-900 px-6 py-12 shadow-xl border border-zinc-800 sm:rounded-xl sm:px-12">
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
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');
  body { font-family: 'Inter', sans-serif; }
</style>
<style type="text/tailwindcss">
  @layer components {
    .auth-label { @apply block text-sm font-medium leading-6 text-zinc-300; }
    .auth-input { @apply block w-full rounded-md border-0 py-2.5 px-3 bg-zinc-950/50 text-zinc-100 shadow-sm ring-1 ring-inset ring-zinc-800 placeholder:text-zinc-600 focus:ring-2 focus:ring-inset focus:ring-zinc-500 sm:text-sm sm:leading-6; }
    .auth-btn { @apply flex w-full justify-center rounded-md bg-zinc-200 px-3 py-2.5 text-sm font-semibold text-zinc-900 shadow-sm hover:bg-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-300 transition-colors; }
    .auth-link { @apply font-semibold leading-6 text-zinc-300 hover:text-white transition-colors; }
  }
</style>{{ end }}`

// errorBanner renders the red alert box when .Error is set. Shared so both
// pages surface validation/server errors identically.
const errorBanner = `{{ define "errorBanner" }}{{ if .Error }}
    <div class="rounded-md bg-red-950/50 p-4 mb-6 border border-red-900">
      <div class="flex">
        <div class="ml-3">
          <h3 class="text-sm font-medium text-red-400">{{ .ErrorLabel }}</h3>
        </div>
      </div>
    </div>
    {{ end }}{{ end }}`
