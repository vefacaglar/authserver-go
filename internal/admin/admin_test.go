package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/store/memory"

	"github.com/google/uuid"
)

const testAdminToken = "test-admin-token-1234567890"

// --- CSRF middleware ---

// The CSRF check is a double-submit against the shared _csrf cookie
// (issued by GET /api/csrf in the oidc package). It applies only to
// state-changing requests that rely on ambient cookie authority:
// Bearer-token requests are exempt, safe methods are always allowed.

func csrfTestHandler() http.Handler {
	return CSRFMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func TestCSRFMiddleware_AllowsSafeMethods(t *testing.T) {
	rr := httptest.NewRecorder()
	csrfTestHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/api/clients", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("GET status = %d, want 200", rr.Code)
	}
}

func TestCSRFMiddleware_RejectsSessionPOSTWithoutToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/api/clients", nil)
	req = withAuthMethod(req, authSession)
	rr := httptest.NewRecorder()
	csrfTestHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

func TestCSRFMiddleware_AcceptsSessionPOSTWithMatchingToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/api/clients", nil)
	req = withAuthMethod(req, authSession)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "tok-1"})
	req.Header.Set(csrfHeaderName, "tok-1")
	rr := httptest.NewRecorder()
	csrfTestHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

func TestCSRFMiddleware_RejectsSessionPOSTWithWrongToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/api/clients", nil)
	req = withAuthMethod(req, authSession)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "tok-1"})
	req.Header.Set(csrfHeaderName, "wrong")
	rr := httptest.NewRecorder()
	csrfTestHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

func TestCSRFMiddleware_ExemptsBearerTokenRequests(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/api/clients", nil)
	req = withAuthMethod(req, authToken)
	rr := httptest.NewRecorder()
	csrfTestHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (bearer requests carry no ambient authority)", rr.Code)
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

// stubSessionResolver returns a fixed session for every request.
type stubSessionResolver struct {
	sess *domain.Session
	err  error
}

func (s stubSessionResolver) Resolve(*http.Request) (*domain.Session, error) {
	return s.sess, s.err
}

func TestAuthMiddleware_AcceptsSessionWithAdminRole(t *testing.T) {
	users := memory.NewUserStore()
	now := time.Unix(1700000000, 0)
	_ = users.CreateUser(context.Background(), &domain.User{ID: "u-admin", Username: "root", CreatedAt: now, UpdatedAt: now}, "pw")
	_ = users.AddToRoles(context.Background(), "u-admin", []string{"admin"})
	mw, err := AuthMiddleware(AuthConfig{
		AdminRole: "admin",
		Sessions:  stubSessionResolver{sess: &domain.Session{ID: uuid.New(), UserID: "u-admin"}},
		Users:     users,
	}, nil)
	if err != nil {
		t.Fatalf("AuthMiddleware: %v", err)
	}
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/api/clients", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for admin-role session", rr.Code)
	}
	if got := rr.Header().Get("X-Admin-Auth"); got != "session" {
		t.Errorf("X-Admin-Auth = %q, want session", got)
	}
}

func TestAuthMiddleware_ForbidsSessionWithoutAdminRole(t *testing.T) {
	users := memory.NewUserStore()
	now := time.Unix(1700000000, 0)
	_ = users.CreateUser(context.Background(), &domain.User{ID: "u-plain", Username: "bob", CreatedAt: now, UpdatedAt: now}, "pw")
	_ = users.AddToRoles(context.Background(), "u-plain", []string{"user"})
	mw, _ := AuthMiddleware(AuthConfig{
		AdminRole: "admin",
		Sessions:  stubSessionResolver{sess: &domain.Session{ID: uuid.New(), UserID: "u-plain"}},
		Users:     users,
	}, nil)
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/api/clients", nil))
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for non-admin session", rr.Code)
	}
}

func TestAuthMiddleware_NoSessionFallsThroughTo401(t *testing.T) {
	mw, _ := AuthMiddleware(AuthConfig{
		Token:    testAdminToken,
		Sessions: stubSessionResolver{sess: nil},
		Users:    memory.NewUserStore(),
	}, nil)
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/api/clients", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 when there is no session and no token", rr.Code)
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

func TestAPI_GenerateClientJWKSAndProfile(t *testing.T) {
	srv := newTestAPIServer(t)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/clients/generate-jwks", "application/json", nil)
	if err != nil {
		t.Fatalf("generate-jwks: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("generate-jwks status = %d, want 200", resp.StatusCode)
	}
	var gen struct {
		Kid           string `json:"kid"`
		JWKSJSON      string `json:"jwks_json"`
		PrivateKeyPEM string `json:"private_key_pem"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&gen)
	resp.Body.Close()
	if gen.Kid == "" || gen.JWKSJSON == "" || !strings.Contains(gen.PrivateKeyPEM, "BEGIN PRIVATE KEY") {
		t.Fatalf("unexpected generated keypair: %+v", gen)
	}

	// Register an M2M client using the generated JWKS and profile="m2m".
	body, _ := json.Marshal(clientView{
		ClientID:    "m2m-worker",
		DisplayName: "M2M Worker",
		Profile:     string(domain.ClientProfileM2M),
		JWKSJSON:    gen.JWKSJSON,
	})
	resp, err = http.Post(srv.URL+"/api/clients", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create m2m: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		b, _ := readAll(resp.Body)
		t.Fatalf("create m2m status = %d, want 201; body=%s", resp.StatusCode, b)
	}
	var created clientView
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.Profile != "m2m" || !created.AllowClientCredentials || created.RequirePKCE {
		t.Errorf("unexpected m2m client profile state: %+v", created)
	}
}

func TestAPI_SetUserPassword_EnforcesPolicyAndRevokesEverything(t *testing.T) {
	ctx := context.Background()
	a := newTestAPI(t)
	resets := memory.NewPasswordResetStore()
	a.PasswordResets = resets
	mux := http.NewServeMux()
	a.Mount(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	now := a.Clock.Now().UTC()
	user := &domain.User{ID: "u-1", Username: "alice", SecurityStamp: "stamp-before", CreatedAt: now, UpdatedAt: now}
	if err := a.Users.CreateUser(ctx, user, "OldPassword1"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	var sessionIDs []uuid.UUID
	for i := range 2 {
		sid := uuid.New()
		sessionIDs = append(sessionIDs, sid)
		if err := a.Sessions.Store(ctx, &domain.Session{ID: sid, UserID: "u-1", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatalf("store session: %v", err)
		}
		if err := a.RefreshTokens.Store(ctx, &domain.RefreshToken{
			ID:                uuid.New(),
			TokenHash:         fmt.Sprintf("rt-hash-%d", i),
			ClientID:          "c",
			UserID:            "u-1",
			SessionID:         &sid,
			ExpiresAt:         now.Add(time.Hour),
			AbsoluteExpiresAt: now.Add(24 * time.Hour),
			CreatedAt:         now,
		}); err != nil {
			t.Fatalf("store refresh token: %v", err)
		}
	}
	if err := resets.Create(ctx, &domain.PasswordResetToken{ID: uuid.New(), UserID: "u-1", TokenHash: "reset-hash", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("create reset token: %v", err)
	}

	post := func(pw string) *http.Response {
		t.Helper()
		body, _ := json.Marshal(setPasswordRequest{Password: pw})
		resp, err := http.Post(srv.URL+"/api/users/u-1/password", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("set password: %v", err)
		}
		return resp
	}

	for _, weak := range []string{"short", " LeadingSpace1", strings.Repeat("a", domain.PasswordMaxBytes+1)} {
		resp := post(weak)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("weak password %q: status = %d, want 400", weak, resp.StatusCode)
		}
	}
	if s, _ := a.Sessions.Find(ctx, sessionIDs[0]); s.RevokedAt != nil {
		t.Fatal("rejected password must not revoke sessions")
	}

	resp := post("NewPassword1")
	var res struct {
		SessionsRevoked int `json:"sessions_revoked"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if res.SessionsRevoked != 2 {
		t.Errorf("sessions_revoked = %d, want 2", res.SessionsRevoked)
	}

	if info, _ := a.Users.ValidateCredentials(ctx, "alice", "NewPassword1"); info == nil {
		t.Error("new password does not validate")
	}
	if info, _ := a.Users.ValidateCredentials(ctx, "alice", "OldPassword1"); info != nil {
		t.Error("old password still validates")
	}
	for _, sid := range sessionIDs {
		if s, _ := a.Sessions.Find(ctx, sid); s == nil || s.RevokedAt == nil {
			t.Errorf("session %s not revoked", sid)
		}
	}
	for i := range 2 {
		rt, _ := a.RefreshTokens.FindByHash(ctx, fmt.Sprintf("rt-hash-%d", i))
		if rt == nil || rt.RevokedAt == nil {
			t.Errorf("refresh token %d not revoked", i)
		}
	}
	if u, _ := a.Users.FindUserByID(ctx, "u-1"); u.SecurityStamp == "stamp-before" {
		t.Error("security stamp not rotated")
	}
	if rt, _ := resets.FindByHash(ctx, "reset-hash"); rt.ConsumedAt == nil {
		t.Error("outstanding reset token not invalidated")
	}
	logs, _ := a.AuditLogs.GetPaged(ctx, domain.PagedRequest{Page: 1, PageSize: 10})
	found := false
	for _, l := range logs.Items {
		if l.Action == domain.AuditAdminPasswordSet && l.TargetID == "u-1" {
			found = true
		}
	}
	if !found {
		t.Error("missing admin_password_set audit entry")
	}
}

func TestAPI_DeleteUser_RevokesSessionsAndRefreshTokens(t *testing.T) {
	ctx := context.Background()
	a := newTestAPI(t)
	mux := http.NewServeMux()
	a.Mount(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	now := a.Clock.Now().UTC()
	if err := a.Users.CreateUser(ctx, &domain.User{ID: "u-1", Username: "alice", CreatedAt: now, UpdatedAt: now}, "Password123"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	sid := uuid.New()
	if err := a.Sessions.Store(ctx, &domain.Session{ID: sid, UserID: "u-1", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("store session: %v", err)
	}
	if err := a.RefreshTokens.Store(ctx, &domain.RefreshToken{
		ID: uuid.New(), TokenHash: "rt-hash", ClientID: "c", UserID: "u-1", SessionID: &sid,
		ExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(24 * time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("store refresh token: %v", err)
	}

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/users/u-1", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if s, _ := a.Sessions.Find(ctx, sid); s == nil || s.RevokedAt == nil {
		t.Error("session of deleted user not revoked")
	}
	if rt, _ := a.RefreshTokens.FindByHash(ctx, "rt-hash"); rt == nil || rt.RevokedAt == nil {
		t.Error("refresh token of deleted user not revoked")
	}
	if _, err := a.Users.FindUserByID(ctx, "u-1"); err == nil {
		t.Error("user still exists")
	}
}

func TestAPI_CreateUser_EnforcesPasswordPolicy(t *testing.T) {
	srv := newTestAPIServer(t)
	defer srv.Close()
	body, _ := json.Marshal(createUserRequest{Username: "bob", Password: "short"})
	resp, err := http.Post(srv.URL+"/api/users", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAPI_ConcurrentRotateLeavesOneActiveKey(t *testing.T) {
	a := newTestAPI(t)
	mux := http.NewServeMux()
	a.Mount(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	const rotations = 8
	var wg sync.WaitGroup
	errs := make(chan error, rotations)
	for range rotations {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Post(srv.URL+"/api/keys/rotate", "application/json", nil)
			if err != nil {
				errs <- err
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				errs <- fmt.Errorf("rotate status = %d, want 201", resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	all, err := a.SigningKeys.GetAll(context.Background())
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	if len(all) != rotations {
		t.Errorf("key count = %d, want %d", len(all), rotations)
	}
	active := 0
	for _, k := range all {
		if k.IsActive {
			active++
		}
	}
	if active != 1 {
		t.Errorf("active key count = %d, want 1", active)
	}
}

func TestAPI_RotateSigningKeyAndUnlockUser(t *testing.T) {
	srv := newTestAPIServer(t)
	defer srv.Close()

	// Rotate signing key creates an active key and strips private PEM.
	resp, err := http.Post(srv.URL+"/api/keys/rotate", "application/json", nil)
	if err != nil {
		t.Fatalf("rotate key: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("rotate status = %d, want 201", resp.StatusCode)
	}
	raw, _ := readAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Errorf("rotate leaked private key: %s", raw)
	}

	// Create user without explicit ID (auto-UUID) and unlock them.
	uBody, _ := json.Marshal(createUserRequest{Username: "alice", Email: "alice@example.com", Password: "Password123!"})
	resp, err = http.Post(srv.URL+"/api/users", "application/json", bytes.NewReader(uBody))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create user status = %d, want 201", resp.StatusCode)
	}
	var u userView
	_ = json.NewDecoder(resp.Body).Decode(&u)
	resp.Body.Close()
	if u.ID == "" {
		t.Fatal("expected auto-generated user ID")
	}

	resp, err = http.Post(srv.URL+"/api/users/"+u.ID+"/unlock", "application/json", nil)
	if err != nil {
		t.Fatalf("unlock user: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("unlock status = %d, want 200", resp.StatusCode)
	}
}
