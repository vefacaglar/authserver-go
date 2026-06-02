package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/store/memory"

	"github.com/google/uuid"
)

const testAdminToken = "test-admin-token-1234567890"

// --- CSRF middleware ---

// §2.5 (plan-2.md) — the admin CSRF cookie must follow the same
// Secure flag as the rest of the server. Under RequireHTTPS=true
// the cookie carries Secure; under RequireHTTPS=false it does not,
// so local dev and httptest work without TLS.
//
// gorilla/csrf names the cookie "_gorilla_csrf" by default. The
// library refuses to set a Secure cookie over a non-TLS request
// (r.TLS == nil), so the two branches of the parameter must be
// exercised differently: the false branch via httptest.NewRequest
// (no TLS), and the true branch via httptest.NewTLSServer which
// makes r.TLS non-nil.
const csrfCookieName = "_gorilla_csrf"

func TestCSRFMiddleware_SecureFalse_OmitsSecureFlag(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	mw := CSRFMiddleware(key, false)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost:5175/admin/", nil)
	h.ServeHTTP(rr, req)

	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == csrfCookieName {
			cookie = c
			break
		}
	}
	if cookie == nil {
		t.Fatal("_gorilla_csrf cookie not set under Secure=false")
	}
	if cookie.Secure {
		t.Errorf("Secure=false: cookie.Secure = true, want false")
	}
}

func TestCSRFMiddleware_SecureTrue_SetsCookieWithSecureFlag(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	mw := CSRFMiddleware(key, true)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewTLSServer(h)
	defer ts.Close()
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/admin/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == csrfCookieName {
			cookie = c
			break
		}
	}
	if cookie == nil {
		t.Fatal("_gorilla_csrf cookie not set")
	}
	if !cookie.Secure {
		t.Errorf("Secure=true over TLS: cookie.Secure = false, want true")
	}
}

// --- Auth middleware ---

func TestAuthMiddleware_RejectsAnonymous(t *testing.T) {
	mw, err := AuthMiddleware(AuthConfig{Token: testAdminToken}, nil)
	if err != nil {
		t.Fatalf("AuthMiddleware: %v", err)
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	rr := httptest.NewRecorder()
	mw(inner).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("WWW-Authenticate = %q, want Bearer", rr.Header().Get("WWW-Authenticate"))
	}
}

func TestAuthMiddleware_AcceptsBearer(t *testing.T) {
	mw, _ := AuthMiddleware(AuthConfig{Token: testAdminToken}, nil)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	rr := httptest.NewRecorder()
	mw(inner).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

func TestAuthMiddleware_AcceptsLegacyHeader(t *testing.T) {
	mw, _ := AuthMiddleware(AuthConfig{Token: testAdminToken}, nil)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	req.Header.Set("X-Admin-Token", testAdminToken)
	rr := httptest.NewRecorder()
	mw(inner).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

func TestAuthMiddleware_RejectsBadToken(t *testing.T) {
	mw, _ := AuthMiddleware(AuthConfig{Token: testAdminToken}, nil)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	req.Header.Set("Authorization", "Bearer not-the-right-token")
	rr := httptest.NewRecorder()
	mw(inner).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestAuthMiddleware_AllowAnonymousBypasses(t *testing.T) {
	mw, err := AuthMiddleware(AuthConfig{AllowAnonymous: true}, nil)
	if err != nil {
		t.Fatalf("AuthMiddleware: %v", err)
	}
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	rr := httptest.NewRecorder()
	mw(inner).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !called {
		t.Errorf("anonymous: code=%d called=%v", rr.Code, called)
	}
	if rr.Header().Get("X-Admin-Auth") != "anonymous" {
		t.Errorf("X-Admin-Auth header missing")
	}
}

func TestAuthMiddleware_RejectsEmptyTokenConfig(t *testing.T) {
	_, err := AuthMiddleware(AuthConfig{Token: ""}, nil)
	if err == nil {
		t.Errorf("expected error when token is empty and not anonymous")
	}
}

// --- API CRUD via direct ServeMux ---

func newTestAPI(t *testing.T) *API {
	t.Helper()
	clk := clock.NewFakeClock(time.Unix(1700000000, 0))
	return &API{
		Clients:       memory.NewClientStore(),
		Scopes:        memory.NewScopeStore(),
		Sessions:      memory.NewSessionStore(),
		RefreshTokens: memory.NewRefreshTokenStore(),
		SigningKeys:   memory.NewSigningKeyStore(),
		AuditLogs:     memory.NewAuditLogStore(),
		Users:         memory.NewUserStore(),
		Roles:         memory.NewRoleStore(),
		Clock:         clk,
		Logger:        nil,
	}
}

func newTestAPIServer(t *testing.T) *httptest.Server {
	t.Helper()
	a := newTestAPI(t)
	mux := http.NewServeMux()
	a.Mount(mux)
	return httptest.NewServer(mux)
}

func TestAPI_ClientCRUD(t *testing.T) {
	srv := newTestAPIServer(t)
	defer srv.Close()

	// List empty.
	resp, err := http.Get(srv.URL + "/api/clients")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var listBody struct {
		Items      []clientView `json:"items"`
		TotalCount int          `json:"total_count"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&listBody)
	resp.Body.Close()
	if listBody.TotalCount != 0 {
		t.Errorf("initial list total = %d, want 0", listBody.TotalCount)
	}

	// Create.
	body, _ := json.Marshal(clientView{
		ClientID:                "test-client",
		DisplayName:             "Test",
		RedirectURIs:            []string{"https://app.example/cb"},
		AllowedScopes:           []string{"openid", "profile"},
		TokenEndpointAuthMethod: string(domain.TokenEndpointAuthMethodNone),
	})
	resp, err = http.Post(srv.URL+"/api/clients", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		body, _ := readAll(resp.Body)
		t.Errorf("create status = %d, want 201; body=%s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// List non-empty.
	resp, _ = http.Get(srv.URL + "/api/clients")
	_ = json.NewDecoder(resp.Body).Decode(&listBody)
	resp.Body.Close()
	if listBody.TotalCount != 1 {
		t.Errorf("after create total = %d, want 1", listBody.TotalCount)
	}

	// Delete.
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/clients/test-client", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete status = %d, want 204", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAPI_ClientCRUD_RejectsMissingID(t *testing.T) {
	srv := newTestAPIServer(t)
	defer srv.Close()
	body, _ := json.Marshal(clientView{DisplayName: "no-id"})
	resp, err := http.Post(srv.URL+"/api/clients", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAPI_Keys_StripPrivatePEM(t *testing.T) {
	srv := newTestAPIServer(t)
	defer srv.Close()

	// Seed a signing key with a private PEM.
	api := newTestAPI(t)
	_ = api.SigningKeys.Store(context.Background(), &domain.SigningKey{
		KeyID:         "kid-1",
		Algorithm:     "RS256",
		PrivateKeyPEM: "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----",
		PublicKeyPEM:  "-----BEGIN PUBLIC KEY-----\nPUBLIC\n-----END PUBLIC KEY-----",
		CreatedAt:     time.Unix(1700000000, 0).UTC(),
		IsActive:      true,
	})

	// We registered the server before the seed; need to re-create
	// with the seeded store. For brevity, hit the API we built and
	// rely on the in-memory backing that was used to create the
	// server. The server's backing is the same instance we seeded
	// above, so the GET will see the new key.
	mux := http.NewServeMux()
	api.Mount(mux)
	srv = httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/keys")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := readAll(resp.Body)
	if strings.Contains(string(body), "PRIVATE") {
		t.Errorf("response leaked private PEM: %s", body)
	}
	if !strings.Contains(string(body), "PUBLIC") {
		t.Errorf("response missing public PEM: %s", body)
	}
}

func TestAPI_RefreshTokenList_OmitsTokenHash(t *testing.T) {
	srv := newTestAPIServer(t)
	defer srv.Close()

	api := newTestAPI(t)
	_ = api.RefreshTokens.Store(context.Background(), &domain.RefreshToken{
		ID:                uuidNew(),
		TokenHash:         "super-secret-hash",
		ClientID:          "test-client",
		UserID:            "u-1",
		Scope:             "openid",
		ExpiresAt:         time.Now().Add(time.Hour),
		AbsoluteExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt:         time.Now(),
	})
	mux := http.NewServeMux()
	api.Mount(mux)
	srv = httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/refresh-tokens")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := readAll(resp.Body)
	if strings.Contains(string(body), "super-secret-hash") {
		t.Errorf("response leaked token hash: %s", body)
	}
}

func TestAPI_RefreshToken_Revoke(t *testing.T) {
	srv := newTestAPIServer(t)
	defer srv.Close()

	api := newTestAPI(t)
	id := uuidNew()
	_ = api.RefreshTokens.Store(context.Background(), &domain.RefreshToken{
		ID:                id,
		TokenHash:         "hash-1",
		ClientID:          "test-client",
		UserID:            "u-1",
		Scope:             "openid",
		ExpiresAt:         time.Now().Add(time.Hour),
		AbsoluteExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt:         time.Now(),
	})
	mux := http.NewServeMux()
	api.Mount(mux)
	srv = httptest.NewServer(mux)
	defer srv.Close()

	form := url.Values{}
	form.Set("k", "v") // not used, just so the call has a body
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/refresh-tokens/"+id.String()+"/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
	got, _ := api.RefreshTokens.FindByHash(context.Background(), "hash-1")
	if got == nil || got.RevokedAt == nil {
		t.Errorf("refresh token not revoked: %+v", got)
	}
}

func TestAPI_ScopesCRUD(t *testing.T) {
	srv := newTestAPIServer(t)
	defer srv.Close()
	body, _ := json.Marshal(scopeView{Name: "openid", DisplayName: "OpenID", Required: true})
	resp, err := http.Post(srv.URL+"/api/scopes", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/scopes/openid", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("del: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete status = %d, want 204", resp.StatusCode)
	}
}

func TestAPI_ClientGetUpdateDelete(t *testing.T) {
	srv := newTestAPIServer(t)
	defer srv.Close()

	jwks := `{"keys":[{"kty":"RSA","kid":"test-kid","n":"abc","e":"AQAB"}]}`
	body, _ := json.Marshal(clientView{
		ClientID:                "jwt-client",
		DisplayName:             "JWT Client",
		AllowedScopes:           []string{"openid"},
		TokenEndpointAuthMethod: string(domain.TokenEndpointAuthMethodPrivateKeyJWT),
		JWKSJSON:                jwks,
	})
	resp, err := http.Post(srv.URL+"/api/clients", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		b, _ := readAll(resp.Body)
		t.Fatalf("create status = %d, want 201; body=%s", resp.StatusCode, b)
	}
	resp.Body.Close()

	resp, err = http.Get(srv.URL + "/api/clients/jwt-client")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d, want 200", resp.StatusCode)
	}
	var got clientView
	_ = json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if got.JWKSJSON != jwks {
		t.Errorf("jwks_json = %q, want %q", got.JWKSJSON, jwks)
	}
	if !got.HasJWKS {
		t.Error("has_jwks = false, want true")
	}

	updateBody, _ := json.Marshal(clientView{
		ClientID:                "jwt-client",
		DisplayName:             "Updated Name",
		AllowedScopes:           []string{"openid", "profile"},
		TokenEndpointAuthMethod: string(domain.TokenEndpointAuthMethodPrivateKeyJWT),
		JWKSJSON:                jwks,
	})
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/clients/jwt-client", bytes.NewReader(updateBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := readAll(resp.Body)
		t.Fatalf("update status = %d, want 200; body=%s", resp.StatusCode, b)
	}
	var updated clientView
	_ = json.NewDecoder(resp.Body).Decode(&updated)
	resp.Body.Close()
	if updated.DisplayName != "Updated Name" {
		t.Errorf("display_name = %q, want %q", updated.DisplayName, "Updated Name")
	}

	resp, _ = http.Get(srv.URL + "/api/clients")
	var listBody struct {
		Items []clientView `json:"items"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&listBody)
	resp.Body.Close()
	found := false
	for _, c := range listBody.Items {
		if c.ClientID == "jwt-client" && c.HasJWKS {
			found = true
		}
	}
	if !found {
		t.Error("list missing jwt-client with has_jwks=true")
	}

	req, _ = http.NewRequest(http.MethodDelete, srv.URL+"/api/clients/jwt-client", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete status = %d, want 204", resp.StatusCode)
	}
	resp.Body.Close()

	resp, err = http.Get(srv.URL + "/api/clients/jwt-client")
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("get after delete status = %d, want 404", resp.StatusCode)
	}
}

func TestAPI_ClientCreate_PrivateKeyJWT_RequiresJWKS(t *testing.T) {
	srv := newTestAPIServer(t)
	defer srv.Close()

	body, _ := json.Marshal(clientView{
		ClientID:                "no-jwks",
		TokenEndpointAuthMethod: string(domain.TokenEndpointAuthMethodPrivateKeyJWT),
	})
	resp, err := http.Post(srv.URL+"/api/clients", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAPI_ClientCreate_PrivateKeyJWT_InvalidJWKS(t *testing.T) {
	srv := newTestAPIServer(t)
	defer srv.Close()

	body, _ := json.Marshal(clientView{
		ClientID:                "bad-jwks",
		TokenEndpointAuthMethod: string(domain.TokenEndpointAuthMethodPrivateKeyJWT),
		JWKSJSON:                `{"keys":[]}`,
	})
	resp, err := http.Post(srv.URL+"/api/clients", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAPI_ClientUpdate_NotFound(t *testing.T) {
	srv := newTestAPIServer(t)
	defer srv.Close()

	body, _ := json.Marshal(clientView{DisplayName: "ghost"})
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/clients/nonexistent", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAPI_ClientGet_NotFound(t *testing.T) {
	srv := newTestAPIServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/clients/nonexistent")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// --- helpers ---

func readAll(r interface {
	Read(p []byte) (n int, err error)
}) ([]byte, error) {
	var buf bytes.Buffer
	tmp := make([]byte, 1024)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}
	return buf.Bytes(), nil
}

func uuidNew() uuid.UUID {
	return uuid.New()
}

// newUUID is preserved for compatibility with the inline [16]byte
// id used elsewhere; admin tests use uuid.UUID directly now.
var _ = newUUID

func newUUID() (id [16]byte) { return [16]byte(uuid.New()) }

func TestAPI_ScopeUpdate(t *testing.T) {
	srv := newTestAPIServer(t)
	defer srv.Close()

	// 1. Create a scope
	body, _ := json.Marshal(scopeView{Name: "custom", DisplayName: "Custom Display", Required: true})
	resp, err := http.Post(srv.URL+"/api/scopes", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want 201", resp.StatusCode)
	}

	// 2. Update it
	updateBody, _ := json.Marshal(scopeView{Name: "custom", DisplayName: "Updated Custom Display", Description: "New Desc", Required: false})
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/scopes/custom", bytes.NewReader(updateBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update status = %d, want 200", resp.StatusCode)
	}
	var updated scopeView
	_ = json.NewDecoder(resp.Body).Decode(&updated)
	resp.Body.Close()

	if updated.DisplayName != "Updated Custom Display" || updated.Description != "New Desc" || updated.Required {
		t.Errorf("scope update failed: %+v", updated)
	}
}

func TestAPI_RoleUpdateAndClaims(t *testing.T) {
	srv := newTestAPIServer(t)
	defer srv.Close()

	// 1. Create role
	body, _ := json.Marshal(createRoleRequest{ID: "role-1", Name: "Role One"})
	resp, err := http.Post(srv.URL+"/api/roles", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create role status = %d, want 201", resp.StatusCode)
	}

	// 2. Update role name
	updateBody, _ := json.Marshal(createRoleRequest{ID: "role-1", Name: "Updated Role One"})
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/roles/role-1", bytes.NewReader(updateBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update role status = %d, want 200", resp.StatusCode)
	}
	var updatedRole roleView
	_ = json.NewDecoder(resp.Body).Decode(&updatedRole)
	resp.Body.Close()

	if updatedRole.Name != "Updated Role One" {
		t.Errorf("role update name failed: %+v", updatedRole)
	}

	// 3. Update Role claims
	claimsBody, _ := json.Marshal(setRoleClaimsRequest{
		Claims: []domain.RoleClaim{
			{Type: "permission", Value: "read"},
			{Type: "permission", Value: "write"},
		},
	})
	req, _ = http.NewRequest(http.MethodPut, srv.URL+"/api/roles/role-1/claims", bytes.NewReader(claimsBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put claims: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("set role claims status = %d, want 204", resp.StatusCode)
	}

	// 4. Retrieve Role claims
	resp, err = http.Get(srv.URL + "/api/roles/role-1/claims")
	if err != nil {
		t.Fatalf("get claims: %v", err)
	}
	var getClaimsRes struct {
		Claims []domain.RoleClaim `json:"claims"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&getClaimsRes)
	resp.Body.Close()

	if len(getClaimsRes.Claims) != 2 || getClaimsRes.Claims[0].Value != "read" {
		t.Errorf("get role claims failed: %+v", getClaimsRes.Claims)
	}
}
