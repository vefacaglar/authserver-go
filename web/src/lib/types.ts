// Wire types for the Go JSON APIs. Field names match the snake_case
// JSON tags in internal/oidc and internal/admin exactly.

export interface SessionView {
  authenticated: boolean;
  user_id?: string;
  username?: string;
  email?: string;
  roles?: string[];
  is_admin: boolean;
}

export interface HomeLogin {
  when: string;
  ip: string;
  device: string;
  current: boolean;
}

export interface HomeView {
  username: string;
  email: string;
  logins: HomeLogin[];
  failed_logins: HomeLogin[];
}

export interface ProfileSession {
  id: string;
  created_at: string;
  expires_at: string;
  current: boolean;
}

export interface ProfileView {
  username: string;
  email: string;
  has_other_sessions: boolean;
  sessions: ProfileSession[];
}

// --- admin API ---

export interface Paged<T> {
  items: T[];
  total_count: number;
}

export interface ClientView {
  client_id: string;
  display_name: string;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  allowed_scopes: string[];
  require_pkce: boolean;
  allow_refresh_tokens: boolean;
  allow_client_credentials: boolean;
  token_endpoint_auth_method: string;
  has_jwks: boolean;
  jwks_json?: string;
  access_token_lifetime_seconds: number;
  refresh_token_lifetime_seconds: number;
  refresh_token_absolute_lifetime_seconds: number;
  refresh_token_expiration: number;
  properties?: Record<string, string>;
}

export interface ScopeView {
  name: string;
  display_name: string;
  description: string;
  required: boolean;
  emphasize: boolean;
  properties?: Record<string, string>;
}

export interface AdminSessionView {
  id: string;
  user_id: string;
  created_at: string;
  expires_at: string;
  revoked_at?: string;
}

export interface RefreshTokenView {
  id: string;
  client_id: string;
  user_id: string;
  session_id?: string;
  parent_token_id?: string;
  scope: string;
  expires_at: string;
  absolute_expires_at: string;
  consumed_at?: string;
  revoked_at?: string;
  created_at: string;
}

export interface KeyView {
  kid: string;
  alg: string;
  public_pem: string;
  created_at: string;
  retired_at?: string;
  is_active: boolean;
}

export interface AuditView {
  id: string;
  action: string;
  actor_user_id: string;
  target_type: string;
  target_id: string;
  timestamp: string;
  ip_address?: string;
  user_agent?: string;
  metadata?: string;
}

export interface UserView {
  id: string;
  username: string;
  email: string;
  email_confirmed: boolean;
  two_factor_enabled: boolean;
  lockout_end?: string;
  lockout_enabled: boolean;
  access_failed_count: number;
  created_at: string;
  updated_at: string;
}

export interface RoleView {
  id: string;
  name: string;
}

export interface Claim {
  Type: string;
  Value: string;
}
