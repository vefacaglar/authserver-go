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
