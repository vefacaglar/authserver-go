import { useEffect, useState, type FormEvent } from "react";
import { useLocation } from "react-router";
import { Cpu, Download, Globe, KeyRound, Laptop, Plus, RefreshCw, Sliders } from "lucide-react";
import {
  Badge,
  CopyButton,
  DataTable,
  DurationPicker,
  KeyValueEditor,
  ListHeader,
  Pagination,
  Tabs,
  Th,
  ToggleCard,
  UriListEditor,
  recordToRows,
  rowsToRecord,
  usePagedList,
  useToast,
  type KeyValueRow,
} from "./shared";
import { ConfirmDialog, ErrorBanner, Loading, errorMessage } from "../components/ui";
import { apiDelete, apiGet, apiPost, apiPut } from "../lib/api";
import type { ClientProfile, ClientView, GeneratedJWKSView, Paged, ScopeView } from "../lib/types";

interface ClientFormState {
  profile: ClientProfile;
  client_id: string;
  display_name: string;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  allowed_scopes: string[];
  token_endpoint_auth_method: string;
  jwks_json: string;
  require_pkce: boolean;
  allow_refresh_tokens: boolean;
  allow_client_credentials: boolean;
  access_token_lifetime_seconds: number;
  refresh_token_lifetime_seconds: number;
  refresh_token_absolute_lifetime_seconds: number;
  refresh_expiration: number;
  property_rows: KeyValueRow[];
}

const ARCHETYPES: Array<{
  id: ClientProfile;
  title: string;
  badge: string;
  subtitle: string;
  details: string;
  icon: typeof Laptop;
}> = [
  {
    id: "spa",
    title: "single-page / mobile app",
    badge: "public · pkce",
    subtitle: "react, vue, ios, android, desktop, cli",
    details: "runs in a browser or device that cannot safely store a private key. uses authorization code + pkce (s256).",
    icon: Laptop,
  },
  {
    id: "web",
    title: "backend web application",
    badge: "confidential · private_key_jwt",
    subtitle: "next.js, go, .net, node.js, rails",
    details: "runs on your server. signs users in via browser redirect and authenticates token requests with a public/private keypair.",
    icon: Globe,
  },
  {
    id: "m2m",
    title: "machine-to-machine service",
    badge: "service · client_credentials",
    subtitle: "worker, cron job, microservice, daemon",
    details: "background service with no human sign-in. authenticates directly with a keypair to obtain access tokens.",
    icon: Cpu,
  },
];

const BUILTIN_SCOPE_HINTS: Record<string, { title: string; desc: string }> = {
  openid: {
    title: "openid (user identity)",
    desc: "required for sign-in. includes the user's unique id (sub) in the id token.",
  },
  profile: {
    title: "profile (name & username)",
    desc: "grants access to display name, username, and basic profile claims.",
  },
  email: {
    title: "email (address & verification)",
    desc: "grants access to the user's email address and email_verified status.",
  },
  offline_access: {
    title: "offline_access (refresh tokens)",
    desc: "allows the app to stay signed in by exchanging refresh tokens without re-prompting the user.",
  },
};

function slugifyClientId(name: string): string {
  return name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
}

function detectProfile(c: Partial<ClientView>): ClientProfile {
  if (c.profile === "spa" || c.profile === "web" || c.profile === "m2m" || c.profile === "custom") {
    return c.profile;
  }
  if (c.token_endpoint_auth_method === "private_key_jwt") {
    if (c.allow_client_credentials && (!c.redirect_uris || c.redirect_uris.length === 0) && !c.allow_refresh_tokens) {
      return "m2m";
    }
    if (!c.allow_client_credentials) {
      return "web";
    }
    return "custom";
  }
  return "spa";
}

function toForm(c: Partial<ClientView>, defaultProfile: ClientProfile = "spa"): ClientFormState {
  const profile = c.client_id ? detectProfile(c) : defaultProfile;
  const allowRefresh = c.allow_refresh_tokens ?? profile !== "m2m";
  const defaultScopes =
    profile === "m2m"
      ? ["openid"]
      : allowRefresh
        ? ["openid", "profile", "email", "offline_access"]
        : ["openid", "profile", "email"];

  return {
    profile,
    client_id: c.client_id ?? "",
    display_name: c.display_name ?? "",
    redirect_uris: c.redirect_uris ?? [],
    post_logout_redirect_uris: c.post_logout_redirect_uris ?? [],
    allowed_scopes: c.allowed_scopes?.length ? c.allowed_scopes : defaultScopes,
    token_endpoint_auth_method: c.token_endpoint_auth_method || (profile === "spa" ? "none" : "private_key_jwt"),
    jwks_json: c.jwks_json ?? "",
    require_pkce: c.require_pkce ?? profile !== "m2m",
    allow_refresh_tokens: allowRefresh,
    allow_client_credentials: c.allow_client_credentials ?? profile === "m2m",
    access_token_lifetime_seconds: c.access_token_lifetime_seconds ?? 0,
    refresh_token_lifetime_seconds: c.refresh_token_lifetime_seconds ?? 0,
    refresh_token_absolute_lifetime_seconds: c.refresh_token_absolute_lifetime_seconds ?? 0,
    refresh_expiration: c.refresh_token_expiration ?? 0,
    property_rows: recordToRows(c.properties),
  };
}

function applyArchetype(f: ClientFormState, nextProfile: ClientProfile): ClientFormState {
  if (nextProfile === "spa") {
    const scopes = Array.from(new Set(["openid", "profile", "email", ...f.allowed_scopes]));
    return {
      ...f,
      profile: "spa",
      token_endpoint_auth_method: "none",
      require_pkce: true,
      allow_client_credentials: false,
      allow_refresh_tokens: true,
      allowed_scopes: scopes.includes("offline_access") ? scopes : [...scopes, "offline_access"],
    };
  }
  if (nextProfile === "web") {
    const scopes = Array.from(new Set(["openid", "profile", "email", ...f.allowed_scopes]));
    return {
      ...f,
      profile: "web",
      token_endpoint_auth_method: "private_key_jwt",
      require_pkce: true,
      allow_client_credentials: false,
      allow_refresh_tokens: true,
      allowed_scopes: scopes.includes("offline_access") ? scopes : [...scopes, "offline_access"],
    };
  }
  if (nextProfile === "m2m") {
    return {
      ...f,
      profile: "m2m",
      token_endpoint_auth_method: "private_key_jwt",
      require_pkce: false,
      allow_refresh_tokens: false,
      allow_client_credentials: true,
      redirect_uris: [],
      post_logout_redirect_uris: [],
      allowed_scopes: f.allowed_scopes.filter((s) => s !== "offline_access"),
    };
  }
  return { ...f, profile: "custom" };
}

function fromForm(f: ClientFormState): ClientView {
  const scopesSet = new Set(["openid", ...f.allowed_scopes]);
  if (f.allow_refresh_tokens) {
    scopesSet.add("offline_access");
  } else {
    scopesSet.delete("offline_access");
  }
  return {
    client_id: f.client_id.trim(),
    display_name: f.display_name.trim(),
    profile: f.profile,
    redirect_uris: f.profile === "m2m" ? [] : f.redirect_uris,
    post_logout_redirect_uris: f.profile === "m2m" ? [] : f.post_logout_redirect_uris,
    allowed_scopes: Array.from(scopesSet),
    token_endpoint_auth_method: f.token_endpoint_auth_method,
    jwks_json: f.token_endpoint_auth_method === "private_key_jwt" ? f.jwks_json.trim() || undefined : undefined,
    has_jwks: f.token_endpoint_auth_method === "private_key_jwt" && !!f.jwks_json.trim(),
    require_pkce: f.require_pkce,
    allow_refresh_tokens: f.allow_refresh_tokens,
    allow_client_credentials: f.allow_client_credentials,
    access_token_lifetime_seconds: f.access_token_lifetime_seconds,
    refresh_token_lifetime_seconds: f.refresh_token_lifetime_seconds,
    refresh_token_absolute_lifetime_seconds: f.refresh_token_absolute_lifetime_seconds,
    refresh_token_expiration: f.refresh_expiration,
    properties: rowsToRecord(f.property_rows),
  };
}

type FormTab = "settings" | "lifetimes" | "quickstart";
type View = { kind: "list" } | { kind: "form"; isEdit: boolean; form: ClientFormState; tab: FormTab };

export default function Clients() {
  const toast = useToast();
  const location = useLocation();
  const list = usePagedList<ClientView>("/admin/api/clients");
  const [search, setSearch] = useState("");
  const [profileFilter, setProfileFilter] = useState<string>("all");
  const [view, setView] = useState<View>({ kind: "list" });
  const [idTouched, setIdTouched] = useState(false);
  const [allScopes, setAllScopes] = useState<ScopeView[]>([]);
  const [deleting, setDeleting] = useState<ClientView | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [generatingKey, setGeneratingKey] = useState(false);
  const [generatedKey, setGeneratedKey] = useState<GeneratedJWKSView | null>(null);
  const [showRawJwks, setShowRawJwks] = useState(false);

  useEffect(() => {
    apiGet<Paged<ScopeView>>("/admin/api/scopes")
      .then((r) => setAllScopes(r.items ?? []))
      .catch(() =>
        setAllScopes([
          { name: "openid", display_name: "OpenID", description: "", required: true, emphasize: false },
          { name: "profile", display_name: "Profile", description: "", required: false, emphasize: false },
          { name: "email", display_name: "Email", description: "", required: false, emphasize: false },
          { name: "offline_access", display_name: "Offline access", description: "", required: false, emphasize: false },
        ]),
      );
  }, []);

  useEffect(() => {
    if ((location.state as { create?: boolean } | null)?.create) {
      openCreate();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.state]);

  function openCreate() {
    setFormError(null);
    setGeneratedKey(null);
    setShowRawJwks(false);
    setIdTouched(false);
    setView({ kind: "form", isEdit: false, form: toForm({}, "spa"), tab: "settings" });
  }

  async function openEdit(id: string, initialTab: FormTab = "settings") {
    setFormError(null);
    setGeneratedKey(null);
    setShowRawJwks(false);
    try {
      const c = await apiGet<ClientView>(`/admin/api/clients/${encodeURIComponent(id)}`);
      setView({ kind: "form", isEdit: true, form: toForm(c), tab: initialTab });
    } catch (e) {
      toast(errorMessage(e), "error");
    }
  }

  async function onGenerateKeypair() {
    if (view.kind !== "form") return;
    setGeneratingKey(true);
    setFormError(null);
    try {
      const gen = await apiPost<GeneratedJWKSView>("/admin/api/clients/generate-jwks");
      setGeneratedKey(gen);
      setView({
        ...view,
        form: {
          ...view.form,
          token_endpoint_auth_method: "private_key_jwt",
          jwks_json: gen.jwks_json,
        },
      });
      toast("rsa-2048 keypair generated — copy or download the private key below");
    } catch (e) {
      setFormError(errorMessage(e));
    } finally {
      setGeneratingKey(false);
    }
  }

  function downloadPrivateKey(clientId: string, pem: string) {
    const blob = new Blob([pem], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${clientId || "client"}-private-key.pem`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (view.kind !== "form") return;
    const f = view.form;
    if (!f.client_id.trim()) {
      setFormError("client id is required.");
      return;
    }
    if (f.profile !== "m2m" && f.redirect_uris.length === 0) {
      setFormError("add at least one sign-in callback url (redirect_uri) so users can return to your app after login.");
      return;
    }
    if (f.token_endpoint_auth_method === "private_key_jwt" && !f.jwks_json.trim()) {
      setFormError("this client uses private_key_jwt authentication. click 'generate keypair' or paste a public jwks json.");
      return;
    }

    setBusy(true);
    setFormError(null);
    try {
      const body = fromForm(f);
      if (view.isEdit) {
        await apiPut(`/admin/api/clients/${encodeURIComponent(body.client_id)}`, body);
        toast("client configuration saved");
        setView({ kind: "list" });
      } else {
        const created = await apiPost<ClientView>("/admin/api/clients", body);
        toast("client registered — integration endpoints ready");
        setView({ kind: "form", isEdit: true, form: toForm({ ...created, jwks_json: body.jwks_json }), tab: "quickstart" });
      }
      list.reload();
    } catch (err) {
      setFormError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function onDelete() {
    if (!deleting) return;
    setBusy(true);
    try {
      await apiDelete(`/admin/api/clients/${encodeURIComponent(deleting.client_id)}`);
      toast(`client "${deleting.client_id}" deleted`);
      setDeleting(null);
      setView({ kind: "list" });
      list.reload();
    } catch (e) {
      toast(errorMessage(e), "error");
    } finally {
      setBusy(false);
    }
  }

  if (view.kind === "form") {
    const f = view.form;
    const set = (patch: Partial<ClientFormState>) => setView({ ...view, form: { ...f, ...patch } });
    const origin = window.location.origin;
    const needsCallbacks = f.profile !== "m2m";
    const needsJwks = f.token_endpoint_auth_method === "private_key_jwt";

    return (
      <form onSubmit={onSubmit} className="space-y-6 max-w-5xl">
        {/* Top Action Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-[var(--border)]">
          <div className="space-y-1">
            <div className="flex items-center gap-3 flex-wrap">
              <button
                type="button"
                className="text-xs text-[var(--muted)] hover:text-[var(--accent)] lowercase cursor-pointer bg-transparent border-0 p-0 transition-colors"
                onClick={() => setView({ kind: "list" })}
              >
                ← clients
              </button>
              <span className="text-[var(--border)]">|</span>
              <h1 className="text-[20px] font-semibold text-[var(--text-heading)] lowercase m-0">
                {view.isEdit ? f.display_name || f.client_id : "register new client"}
              </h1>
              {view.isEdit && <Badge tone="zinc">{f.profile}</Badge>}
            </div>
            <p className="text-[13px] text-[var(--muted)] lowercase m-0">
              {view.isEdit
                ? `client_id: ${f.client_id}`
                : "choose your application type below — protocol flags and scopes will be configured automatically."}
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button type="button" className="admin-btn admin-btn-ghost" onClick={() => setView({ kind: "list" })}>
              cancel
            </button>
            <button type="submit" className="admin-btn" disabled={busy}>
              {busy ? "saving…" : view.isEdit ? "save changes" : "register client"}
            </button>
          </div>
        </div>

        <ErrorBanner error={formError} />

        {view.isEdit && (
          <Tabs<FormTab>
            active={view.tab}
            onChange={(tab) => setView({ ...view, tab })}
            tabs={[
              { id: "settings", label: "1. application & security" },
              { id: "lifetimes", label: "2. token lifetimes & metadata" },
              { id: "quickstart", label: "3. integration & endpoints" },
            ]}
          />
        )}

        {view.tab === "quickstart" && view.isEdit ? (
          <div className="space-y-6">
            <section className="bg-[var(--bg)] border border-[var(--border)] p-6 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-[15px] font-semibold text-[var(--text-heading)] lowercase m-0">
                    oidc endpoints & client credentials
                  </h2>
                  <p className="text-xs text-[var(--muted)] lowercase mt-1 m-0">
                    copy these values into your application’s oauth2 / openid connect configuration.
                  </p>
                </div>
                <Badge tone="emerald">{f.profile}</Badge>
              </div>
              <div className="divide-y divide-[var(--border)] border border-[var(--border)] bg-[var(--bg)] text-xs">
                {[
                  ["client_id", f.client_id],
                  ["issuer / authority", origin],
                  ["discovery document", `${origin}/.well-known/openid-configuration`],
                  ["authorization endpoint", `${origin}/connect/authorize`],
                  ["token endpoint", `${origin}/connect/token`],
                  ["userinfo endpoint", `${origin}/connect/userinfo`],
                  ["end session (logout)", `${origin}/connect/logout`],
                  ["jwks uri", `${origin}/.well-known/jwks.json`],
                ].map(([label, val]) => (
                  <div key={label} className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 px-4 py-2.5">
                    <span className="text-[var(--muted)] lowercase w-48 shrink-0">{label}</span>
                    <code className="text-[var(--text-heading)] break-all flex-1">{val}</code>
                    <CopyButton value={val} />
                  </div>
                ))}
              </div>
            </section>

            <section className="bg-[var(--bg)] border border-[var(--border)] p-6 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-[15px] font-semibold text-[var(--text-heading)] lowercase m-0">
                  ready-to-use .env snippet
                </h2>
                <CopyButton
                  label="copy .env"
                  value={[
                    `OIDC_ISSUER=${origin}`,
                    `OIDC_CLIENT_ID=${f.client_id}`,
                    f.redirect_uris[0] ? `OIDC_REDIRECT_URI=${f.redirect_uris[0]}` : null,
                    `OIDC_SCOPES="${f.allowed_scopes.join(" ")}"`,
                  ]
                    .filter(Boolean)
                    .join("\n")}
                />
              </div>
              <pre className="p-4 bg-[var(--bg)] border border-[var(--border)] text-xs text-[var(--text)] overflow-x-auto leading-relaxed m-0">
                {[
                  `OIDC_ISSUER=${origin}`,
                  `OIDC_CLIENT_ID=${f.client_id}`,
                  f.redirect_uris[0] ? `OIDC_REDIRECT_URI=${f.redirect_uris[0]}` : null,
                  `OIDC_SCOPES="${f.allowed_scopes.join(" ")}"`,
                ]
                  .filter(Boolean)
                  .join("\n")}
              </pre>
            </section>
          </div>
        ) : view.tab === "lifetimes" ? (
          <div className="space-y-6">
            <section className="bg-[var(--bg)] border border-[var(--border)] p-6 space-y-4">
              <div>
                <h2 className="text-[15px] font-semibold text-[var(--text-heading)] lowercase m-0">token lifetimes</h2>
                <p className="text-xs text-[var(--muted)] lowercase mt-1 m-0">
                  pick a preset duration or leave on server default.
                </p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <DurationPicker
                  label="access token lifetime"
                  defaultLabel="1 hour"
                  seconds={f.access_token_lifetime_seconds}
                  onChange={(s) => set({ access_token_lifetime_seconds: s })}
                  presets={[
                    { label: "server default", seconds: 0 },
                    { label: "5 min", seconds: 300 },
                    { label: "15 min", seconds: 900 },
                    { label: "30 min", seconds: 1800 },
                    { label: "1 hour", seconds: 3600 },
                    { label: "12 hours", seconds: 43200 },
                    { label: "24 hours", seconds: 86400 },
                  ]}
                />
                {f.allow_refresh_tokens && (
                  <>
                    <DurationPicker
                      label="refresh token sliding lifetime"
                      defaultLabel="30 days"
                      seconds={f.refresh_token_lifetime_seconds}
                      onChange={(s) => set({ refresh_token_lifetime_seconds: s })}
                      presets={[
                        { label: "server default", seconds: 0 },
                        { label: "24 hours", seconds: 86400 },
                        { label: "7 days", seconds: 604800 },
                        { label: "14 days", seconds: 1209600 },
                        { label: "30 days", seconds: 2592000 },
                        { label: "90 days", seconds: 7776000 },
                      ]}
                    />
                    <DurationPicker
                      label="refresh token absolute maximum"
                      defaultLabel="30 days"
                      seconds={f.refresh_token_absolute_lifetime_seconds}
                      onChange={(s) => set({ refresh_token_absolute_lifetime_seconds: s })}
                      presets={[
                        { label: "server default", seconds: 0 },
                        { label: "7 days", seconds: 604800 },
                        { label: "30 days", seconds: 2592000 },
                        { label: "90 days", seconds: 7776000 },
                        { label: "180 days", seconds: 15552000 },
                      ]}
                    />
                    <div className="border border-[var(--border)] bg-[var(--bg)] p-4 space-y-3">
                      <span className="text-xs text-[var(--muted)] lowercase block">refresh expiration mode</span>
                      <div className="grid grid-cols-2 gap-2">
                        {[
                          { val: 0, title: "sliding window", desc: "extends lifetime on each token refresh up to absolute max" },
                          { val: 1, title: "fixed / absolute", desc: "expires strictly at the initial lifetime regardless of activity" },
                        ].map((opt) => (
                          <button
                            key={opt.val}
                            type="button"
                            onClick={() => set({ refresh_expiration: opt.val })}
                            className={`p-3 border text-left transition-colors cursor-pointer bg-[var(--bg)] ${
                              f.refresh_expiration === opt.val
                                ? "border-[var(--accent)] text-[var(--text-heading)]"
                                : "border-[var(--border)] text-[var(--text)] hover:border-[var(--muted)]"
                            }`}
                          >
                            <div className="text-xs font-semibold lowercase">{opt.title}</div>
                            <div className="text-[11px] text-[var(--muted)] lowercase mt-1">{opt.desc}</div>
                          </button>
                        ))}
                      </div>
                    </div>
                  </>
                )}
              </div>
            </section>

            <section className="bg-[var(--bg)] border border-[var(--border)] p-6 space-y-4">
              <div>
                <h2 className="text-[15px] font-semibold text-[var(--text-heading)] lowercase m-0">
                  custom metadata properties
                </h2>
                <p className="text-xs text-[var(--muted)] lowercase mt-1 m-0">
                  optional key-value tags stored with this client (e.g. owning team, environment, internal notes).
                </p>
              </div>
              <KeyValueEditor rows={f.property_rows} onChange={(rows) => set({ property_rows: rows })} />
            </section>
          </div>
        ) : (
          /* Main Settings Tab (or Create Flow) */
          <div className="space-y-6">
            {/* Step 1: Archetype Selector */}
            <section className="bg-[var(--bg)] border border-[var(--border)] p-6 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-[15px] font-semibold text-[var(--text-heading)] lowercase m-0">
                    1. what type of application is this?
                  </h2>
                  <p className="text-xs text-[var(--muted)] lowercase mt-1 m-0">
                    select an application profile — we’ll set the right oauth2 grants and security defaults for you.
                  </p>
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {ARCHETYPES.map((arch) => {
                  const Icon = arch.icon;
                  const active = f.profile === arch.id;
                  return (
                    <button
                      key={arch.id}
                      type="button"
                      onClick={() => setView({ ...view, form: applyArchetype(f, arch.id) })}
                      className={`p-4 border text-left transition-all flex flex-col justify-between gap-3 cursor-pointer bg-[var(--bg)] ${
                        active
                          ? "border-[var(--accent)]"
                          : "border-[var(--border)] hover:border-[var(--muted)]"
                      }`}
                    >
                      <div className="space-y-2">
                        <div className="flex items-center justify-between gap-2">
                          <Icon className={`w-4 h-4 ${active ? "text-[var(--accent)]" : "text-[var(--muted)]"}`} />
                          <span
                            className={`text-[11px] px-2 py-0.5 border lowercase ${
                              active
                                ? "bg-[var(--text-heading)] text-[var(--bg)] border-[var(--text-heading)] font-semibold"
                                : "border-[var(--border)] text-[var(--muted)]"
                            }`}
                          >
                            {arch.badge}
                          </span>
                        </div>
                        <div className="text-[14px] font-semibold text-[var(--text-heading)] lowercase">{arch.title}</div>
                        <div className="text-[12px] text-[var(--muted)] lowercase">{arch.subtitle}</div>
                      </div>
                      <p className="text-[12px] text-[var(--muted)] lowercase leading-relaxed border-t border-[var(--border)] pt-2 m-0">
                        {arch.details}
                      </p>
                    </button>
                  );
                })}
              </div>
            </section>

            {/* Step 2: Identity (Name & Client ID) */}
            <section className="bg-[var(--bg)] border border-[var(--border)] p-6 space-y-4">
              <div>
                <h2 className="text-[15px] font-semibold text-[var(--text-heading)] lowercase m-0">
                  2. application identity
                </h2>
                <p className="text-xs text-[var(--muted)] lowercase mt-1 m-0">
                  give your app a human-readable name and a unique client_id used in oauth requests.
                </p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div>
                  <label className="auth-label">application display name *</label>
                  <input
                    className="input"
                    required
                    placeholder="e.g. Customer Web Portal"
                    value={f.display_name}
                    onChange={(e) => {
                      const name = e.target.value;
                      const nextId = !view.isEdit && !idTouched ? slugifyClientId(name) : f.client_id;
                      set({ display_name: name, client_id: nextId });
                    }}
                  />
                  <p className="text-[12px] text-[var(--muted)] lowercase mt-1.5 m-0">
                    shown on login and consent screens.
                  </p>
                </div>
                <div>
                  <div className="flex items-center justify-between">
                    <label className="auth-label">client_id (unique identifier) *</label>
                    {view.isEdit && <CopyButton value={f.client_id} label="copy id" />}
                  </div>
                  <input
                    className="input"
                    required
                    readOnly={view.isEdit}
                    placeholder="e.g. customer-web-portal"
                    value={f.client_id}
                    onChange={(e) => {
                      setIdTouched(true);
                      set({ client_id: e.target.value });
                    }}
                  />
                  <p className="text-[12px] text-[var(--muted)] lowercase mt-1.5 m-0">
                    {view.isEdit
                      ? "client_id cannot be changed after creation."
                      : "auto-filled from the name above, or type your own."}
                  </p>
                </div>
              </div>
            </section>

            {/* Step 3: Callback URLs (only for interactive apps: SPA / Web / Custom) */}
            {needsCallbacks && (
              <section className="bg-[var(--bg)] border border-[var(--border)] p-6 space-y-5">
                <div>
                  <h2 className="text-[15px] font-semibold text-[var(--text-heading)] lowercase m-0">
                    3. sign-in & sign-out redirect urls
                  </h2>
                  <p className="text-xs text-[var(--muted)] lowercase mt-1 m-0">
                    for security, we only redirect users to exact urls registered here. type a url and press enter or click add.
                  </p>
                </div>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div>
                    <label className="auth-label">sign-in callback urls (redirect_uris) *</label>
                    <UriListEditor
                      items={f.redirect_uris}
                      onChange={(redirect_uris) => set({ redirect_uris })}
                      placeholder="https://app.example.com/auth/callback"
                      emptyHint="no callback urls added yet — add at least one url where users return after sign-in."
                      presets={[
                        { label: "localhost:3000/callback", url: "http://localhost:3000/callback" },
                        { label: "localhost:5173/callback", url: "http://localhost:5173/callback" },
                        { label: "localhost:8080/callback", url: "http://localhost:8080/callback" },
                      ]}
                    />
                  </div>
                  <div>
                    <label className="auth-label">after sign-out urls (post_logout_redirect_uris — optional)</label>
                    <UriListEditor
                      items={f.post_logout_redirect_uris}
                      onChange={(post_logout_redirect_uris) => set({ post_logout_redirect_uris })}
                      placeholder="https://app.example.com/"
                      emptyHint="no post-logout urls added (optional)."
                      presets={[
                        { label: "localhost:3000", url: "http://localhost:3000/" },
                        { label: "localhost:5173", url: "http://localhost:5173/" },
                      ]}
                    />
                  </div>
                </div>
              </section>
            )}

            {/* Step 4: Client Keypair / Authentication (for Confidential Web & M2M) */}
            {needsJwks && (
              <section className="bg-[var(--bg)] border border-[var(--border)] p-6 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                  <div>
                    <h2 className="text-[15px] font-semibold text-[var(--text-heading)] lowercase flex items-center gap-2 m-0">
                      <KeyRound className="w-4 h-4 text-[var(--accent)]" />
                      {needsCallbacks ? "4." : "3."} client keypair authentication (private_key_jwt)
                    </h2>
                    <p className="text-xs text-[var(--muted)] lowercase mt-1 m-0">
                      instead of a shared password, your backend signs a short-lived jwt with its private key; we verify it using the public jwks below.
                    </p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      className="admin-btn"
                      disabled={generatingKey}
                      onClick={() => void onGenerateKeypair()}
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${generatingKey ? "animate-spin" : ""}`} />
                      {generatingKey ? "generating…" : f.jwks_json ? "generate new keypair" : "generate keypair"}
                    </button>
                    <button
                      type="button"
                      className="admin-btn admin-btn-ghost"
                      onClick={() => setShowRawJwks(!showRawJwks)}
                    >
                      {showRawJwks ? "hide jwks json" : "paste / view jwks json"}
                    </button>
                  </div>
                </div>

                {generatedKey && (
                  <div className="border border-[var(--accent)] bg-[var(--accent)]/5 p-4 space-y-3">
                    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                      <div>
                        <span className="text-xs font-semibold text-[var(--accent)] lowercase block">
                          save your private key now (kid: {generatedKey.kid})
                        </span>
                        <span className="text-[12px] text-[var(--muted)] lowercase">
                          the public key has been filled into this client automatically. the private key below is never stored on the server.
                        </span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <CopyButton value={generatedKey.private_key_pem} label="copy private key" />
                        <button
                          type="button"
                          className="admin-btn"
                          onClick={() => downloadPrivateKey(f.client_id, generatedKey.private_key_pem)}
                        >
                          <Download className="w-3.5 h-3.5" />
                          download .pem
                        </button>
                      </div>
                    </div>
                    <pre className="p-3 bg-[var(--bg)] border border-[var(--border)] text-[11px] text-[var(--text)] overflow-x-auto max-h-40 select-all m-0">
                      {generatedKey.private_key_pem}
                    </pre>
                  </div>
                )}

                {!generatedKey && f.jwks_json && !showRawJwks && (
                  <div className="flex items-center justify-between border border-[var(--success)] bg-[var(--success)]/10 px-4 py-3 text-xs">
                    <span className="text-[var(--success)] lowercase">
                      ✓ public jwks keyset is configured for this client.
                    </span>
                    <button type="button" className="auth-link" onClick={() => setShowRawJwks(true)}>
                      inspect / edit json
                    </button>
                  </div>
                )}

                {(!f.jwks_json || showRawJwks) && (
                  <div>
                    <label className="auth-label">public jwk set (jwks_json) *</label>
                    <textarea
                      className="input h-32 whitespace-pre text-xs"
                      placeholder='click "generate keypair" above or paste {"keys":[{"kty":"RSA","kid":"...","n":"...","e":"AQAB"}]}'
                      value={f.jwks_json}
                      onChange={(e) => set({ jwks_json: e.target.value })}
                    />
                  </div>
                )}
              </section>
            )}

            {/* Step 5: Permissions / Scopes */}
            <section className="bg-[var(--bg)] border border-[var(--border)] p-6 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-[15px] font-semibold text-[var(--text-heading)] lowercase m-0">
                    {needsCallbacks && needsJwks ? "5." : needsCallbacks || needsJwks ? "4." : "3."} permissions & scopes (allowed_scopes)
                  </h2>
                  <p className="text-xs text-[var(--muted)] lowercase mt-1 m-0">
                    choose which user claims and token capabilities this client is allowed to request.
                  </p>
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {allScopes
                  .filter((sc) => (f.profile === "m2m" ? sc.name !== "offline_access" : true))
                  .map((sc) => {
                    const isOpenId = sc.name === "openid";
                    const checked = isOpenId || f.allowed_scopes.includes(sc.name);
                    const hint = BUILTIN_SCOPE_HINTS[sc.name];
                    return (
                      <ToggleCard
                        key={sc.name}
                        checked={checked}
                        disabled={isOpenId}
                        title={hint ? hint.title : sc.display_name ? `${sc.name} (${sc.display_name})` : sc.name}
                        description={hint ? hint.desc : sc.description || "custom scope"}
                        badge={isOpenId ? <Badge tone="zinc">always on</Badge> : undefined}
                        onChange={(next) => {
                          const nextScopes = next
                            ? Array.from(new Set([...f.allowed_scopes, sc.name]))
                            : f.allowed_scopes.filter((x) => x !== sc.name);
                          const patch: Partial<ClientFormState> = { allowed_scopes: nextScopes };
                          if (sc.name === "offline_access") {
                            patch.allow_refresh_tokens = next;
                          }
                          set(patch);
                        }}
                      />
                    );
                  })}
              </div>
            </section>

            {/* Step 6: Protocol Capabilities & Overrides */}
            <section className="bg-[var(--bg)] border border-[var(--border)] p-6 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-[15px] font-semibold text-[var(--text-heading)] lowercase flex items-center gap-2 m-0">
                    <Sliders className="w-4 h-4 text-[var(--muted)]" />
                    security & grant capabilities
                  </h2>
                  <p className="text-xs text-[var(--muted)] lowercase mt-1 m-0">
                    automatically pre-configured for the <span className="text-[var(--text-heading)]">{f.profile}</span> profile — toggle below if you need a custom hybrid setup.
                  </p>
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <ToggleCard
                  checked={f.require_pkce}
                  disabled={f.token_endpoint_auth_method === "none"}
                  title="require pkce (s256)"
                  description="protects authorization codes against interception. mandatory for public clients."
                  badge={f.token_endpoint_auth_method === "none" ? <Badge tone="emerald">enforced</Badge> : undefined}
                  onChange={(require_pkce) => set({ require_pkce })}
                />
                <ToggleCard
                  checked={f.allow_refresh_tokens}
                  disabled={f.profile === "m2m"}
                  title="issue refresh tokens"
                  description="enables the refresh_token grant and offline_access scope for long-lived sessions."
                  onChange={(allow_refresh_tokens) => {
                    const nextScopes = allow_refresh_tokens
                      ? Array.from(new Set([...f.allowed_scopes, "offline_access"]))
                      : f.allowed_scopes.filter((x) => x !== "offline_access");
                    set({ allow_refresh_tokens, allowed_scopes: nextScopes });
                  }}
                />
                <ToggleCard
                  checked={f.allow_client_credentials}
                  disabled={f.token_endpoint_auth_method === "none"}
                  title="client_credentials grant"
                  description="allows server-to-server token issuance without a user (requires private_key_jwt)."
                  onChange={(allow_client_credentials) => set({ allow_client_credentials })}
                />
              </div>
            </section>
          </div>
        )}

        {/* Bottom Action Bar (Danger Zone on left, Save/Cancel on right) */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pt-4 border-t border-[var(--border)]">
          <div>
            {view.isEdit && (
              <button
                type="button"
                className="admin-btn admin-btn-danger"
                onClick={() => setDeleting({ client_id: f.client_id, display_name: f.display_name } as ClientView)}
              >
                delete client…
              </button>
            )}
          </div>
          <div className="flex items-center justify-end gap-2">
            <button type="button" className="admin-btn admin-btn-ghost" onClick={() => setView({ kind: "list" })}>
              cancel
            </button>
            <button type="submit" className="admin-btn" disabled={busy}>
              {busy ? "saving…" : view.isEdit ? "save changes" : "register client"}
            </button>
          </div>
        </div>

        {deleting && (
          <ConfirmDialog
            title="delete client"
            message={`are you sure you want to permanently delete client "${deleting.client_id}"? applications using this client_id will immediately stop working.`}
            confirmLabel="delete client"
            busy={busy}
            onConfirm={() => void onDelete()}
            onClose={() => setDeleting(null)}
          />
        )}
      </form>
    );
  }

  const visible = list.items.filter((c) => {
    const p = detectProfile(c);
    if (profileFilter !== "all" && p !== profileFilter) return false;
    const q = search.toLowerCase();
    return (
      c.client_id.toLowerCase().includes(q) ||
      (c.display_name ?? "").toLowerCase().includes(q) ||
      (c.redirect_uris ?? []).some((u) => u.toLowerCase().includes(q))
    );
  });

  return (
    <>
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-[20px] font-semibold text-[var(--text-heading)] lowercase m-0">clients</h1>
          <p className="text-[13px] text-[var(--muted)] lowercase mt-1 m-0">
            registered oauth2 and openid connect applications ({list.total} total)
          </p>
        </div>
        <button type="button" className="admin-btn" onClick={openCreate}>
          <Plus className="w-3.5 h-3.5" />
          register client
        </button>
      </div>

      <ErrorBanner error={list.error} />

      <ListHeader
        search={search}
        onSearch={setSearch}
        searchPlaceholder="filter by client_id, name, or callback url…"
        filters={
          <div className="flex items-center gap-1.5">
            {[
              { id: "all", label: "all" },
              { id: "spa", label: "spa / public" },
              { id: "web", label: "web app" },
              { id: "m2m", label: "m2m service" },
            ].map((f) => (
              <button
                key={f.id}
                type="button"
                onClick={() => setProfileFilter(f.id)}
                className={`chip ${profileFilter === f.id ? "chip-active" : ""}`}
              >
                {f.label}
              </button>
            ))}
          </div>
        }
      />

      {list.loading && <Loading text="loading clients…" />}
      {!list.loading && (
        <>
          <DataTable
            head={
              <>
                <Th>application</Th>
                <Th>type</Th>
                <Th>callback / grants</Th>
                <Th>scopes</Th>
                <Th right>actions</Th>
              </>
            }
          >
            {visible.map((c) => {
              const prof = detectProfile(c);
              return (
                <tr key={c.client_id} className="hover:bg-[var(--border)]/35 transition-colors">
                  <td className="p-4">
                    <button
                      type="button"
                      onClick={() => void openEdit(c.client_id)}
                      className="text-left group block cursor-pointer bg-transparent border-0 p-0"
                    >
                      <span className="text-[var(--text-heading)] font-semibold group-hover:text-[var(--accent)] transition-colors">
                        {c.display_name || c.client_id}
                      </span>
                      <span className="block text-xs text-[var(--muted)] mt-0.5">{c.client_id}</span>
                    </button>
                  </td>
                  <td className="p-4 whitespace-nowrap">
                    <Badge tone={prof === "spa" ? "zinc" : prof === "m2m" ? "amber" : "emerald"}>
                      {prof === "spa" ? "spa · public" : prof === "m2m" ? "m2m · service" : prof === "web" ? "web · confidential" : "custom"}
                    </Badge>
                  </td>
                  <td className="p-4 text-xs text-[var(--text)]">
                    {prof === "m2m" ? (
                      <span className="text-[var(--muted)]">client_credentials (no browser redirect)</span>
                    ) : c.redirect_uris?.length ? (
                      <span className="break-all">
                        {c.redirect_uris[0]}
                        {c.redirect_uris.length > 1 && (
                          <span className="text-[var(--muted)] ml-1">(+{c.redirect_uris.length - 1} more)</span>
                        )}
                      </span>
                    ) : (
                      <span className="text-[var(--warning)]">no callback url set</span>
                    )}
                  </td>
                  <td className="p-4 text-[var(--muted)] text-xs">
                    <div className="flex flex-wrap gap-1">
                      {(c.allowed_scopes ?? []).map((s) => (
                        <span key={s} className="px-1.5 py-0.5 bg-[var(--bg)] border border-[var(--border)] text-[11px] text-[var(--muted)]">
                          {s}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="p-4 text-right whitespace-nowrap space-x-2">
                    <CopyButton value={c.client_id} label="id" />
                    <button
                      type="button"
                      className="admin-btn admin-btn-ghost"
                      onClick={() => void openEdit(c.client_id, "quickstart")}
                    >
                      endpoints
                    </button>
                    <button
                      type="button"
                      className="admin-btn"
                      onClick={() => void openEdit(c.client_id, "settings")}
                    >
                      configure
                    </button>
                  </td>
                </tr>
              );
            })}
            {visible.length === 0 && (
              <tr>
                <td colSpan={5} className="p-6 text-sm text-[var(--muted)] lowercase text-center">
                  no clients match your filter.
                </td>
              </tr>
            )}
          </DataTable>
          <Pagination page={list.page} pageSize={list.pageSize} total={list.total} onPage={(p) => void list.load(p)} />
        </>
      )}
    </>
  );
}
