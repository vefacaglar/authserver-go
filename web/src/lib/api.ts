// Same-origin API client for the Go JSON APIs.
//
// CSRF: the server uses a double-submit cookie. GET /api/csrf sets the
// HttpOnly _csrf cookie and returns the token in JSON; we cache the
// token in memory and echo it in the X-CSRF-Token header on every
// state-changing request. On a 403 antiforgery_failed we fetch a fresh
// token once and retry (the cookie may have rotated).

export class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

let csrfToken: string | null = null;
let csrfPromise: Promise<string> | null = null;

export function getCSRFToken(force = false): Promise<string> {
  if (!force && csrfToken) return Promise.resolve(csrfToken);
  if (!force && csrfPromise) return csrfPromise;
  csrfPromise = fetch("/api/csrf", { credentials: "same-origin" })
    .then(async (r) => {
      if (!r.ok) throw new ApiError(r.status, "csrf_failed", "could not obtain a csrf token");
      const body = (await r.json()) as { csrf_token: string };
      csrfToken = body.csrf_token;
      return csrfToken;
    })
    .finally(() => {
      csrfPromise = null;
    });
  return csrfPromise;
}

interface ErrorBody {
  error?: string;
  error_description?: string;
  detail?: string;
}

async function toApiError(resp: Response): Promise<ApiError> {
  let body: ErrorBody = {};
  try {
    body = (await resp.json()) as ErrorBody;
  } catch {
    // Non-JSON error body; fall through to the status-based message.
  }
  const code = body.error ?? "request_failed";
  const message = body.error_description ?? body.detail ?? body.error ?? `request failed (${resp.status})`;
  return new ApiError(resp.status, code, message);
}

export interface ApiOptions {
  method?: string;
  body?: unknown;
}

export async function apiFetch<T>(path: string, opts: ApiOptions = {}): Promise<T> {
  const method = (opts.method ?? "GET").toUpperCase();
  const mutating = method !== "GET" && method !== "HEAD";

  const send = async (): Promise<Response> => {
    const headers: Record<string, string> = {};
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    if (mutating) headers["X-CSRF-Token"] = await getCSRFToken();
    return fetch(path, {
      method,
      credentials: "same-origin",
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
  };

  let resp = await send();
  if (resp.status === 403 && mutating) {
    // Possibly a stale CSRF token: refresh once and retry. A genuine
    // authorization 403 will simply come back again.
    const peek = resp.clone();
    let code = "";
    try {
      code = ((await peek.json()) as ErrorBody).error ?? "";
    } catch {
      // ignore
    }
    if (code === "antiforgery_failed") {
      await getCSRFToken(true);
      resp = await send();
    }
  }
  if (!resp.ok) throw await toApiError(resp);
  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

export const apiGet = <T,>(path: string) => apiFetch<T>(path);
export const apiPost = <T,>(path: string, body?: unknown) => apiFetch<T>(path, { method: "POST", body: body ?? {} });
export const apiPut = <T,>(path: string, body: unknown) => apiFetch<T>(path, { method: "PUT", body });
export const apiDelete = (path: string) => apiFetch<void>(path, { method: "DELETE" });
