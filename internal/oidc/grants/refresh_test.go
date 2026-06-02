package grants

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/store"
	"go-authserver/internal/store/memory"
	"go-authserver/internal/token"

	"github.com/google/uuid"
)

// newTestRefresh wires a minimal but real RefreshGrant against in-memory
// stores. The returned helpers make tests easy to write: a function to
// mint a refresh token, and a function to look it up by hash so the
// CAS-driven reuse path can be exercised.
func newTestRefresh(t *testing.T) (*RefreshGrant, *memory.RefreshTokenStore, *memory.AuditLogStore, *domain.Client) {
	t.Helper()
	clk := clock.NewFakeClock(time.Unix(1700000000, 0))
	rt := memory.NewRefreshTokenStore()
	sessions := memory.NewSessionStore()
	clients := memory.NewClientStore()
	users := memory.NewUserStore()
	auditLogs := memory.NewAuditLogStore()
	keys := token.NewKeyManager(memory.NewSigningKeyStore(), clk)
	issuer := token.NewIssuer("https://auth.example.com", keys, clk)

	now := clk.Now()
	_ = users.CreateUser(context.Background(), &domain.User{
		ID:        "u-1",
		Username:  "alice",
		Email:     "alice@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	}, "ignored")
	_ = users.AddUserClaims(context.Background(), "u-1", []domain.UserClaim{
		{Type: "preferred_username", Value: "alice"},
		{Type: "name", Value: "Alice"},
		{Type: "email", Value: "alice@example.com"},
		{Type: "email_verified", Value: "true"},
	})
	testClient := &domain.Client{
		ClientID:                "client-1",
		DisplayName:             "Test Client",
		RedirectURIs:            []string{"https://app.example/cb"},
		AllowedScopes:           []string{"openid", "profile", "email", "offline_access"},
		RequirePKCE:             true,
		AllowRefreshTokens:      true,
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodNone,
	}
	_ = clients.Store(context.Background(), testClient)

	g := &RefreshGrant{
		RefreshTokens: rt,
		Sessions:      sessions,
		Clients:       clients,
		Users:         users,
		AuditLogs:     auditLogs,
		Issuer:        issuer,
		Clock:         clk,
		Logger:        nil,
		Cfg: RefreshConfig{
			AccessTokenLifetime:          time.Hour,
			IDTokenLifetime:              time.Hour,
			RefreshTokenLifetime:         24 * time.Hour,
			RefreshTokenAbsoluteLifetime: 24 * time.Hour,
			DetectReuse:                  true,
		},
	}
	return g, rt, auditLogs, testClient
}

// mintRefresh inserts a refresh token into the store, returning the raw
// value the client would have. sessionID is the SSO session the token is
// bound to (used by RevokeBySessionID).
func mintRefresh(t *testing.T, rt *memory.RefreshTokenStore, clk clock.Clock, sessionID uuid.UUID) string {
	t.Helper()
	raw, hash, err := token.NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken: %v", err)
	}
	now := clk.Now().UTC()
	sid := sessionID
	if err := rt.Store(context.Background(), &domain.RefreshToken{
		ID:                id1(),
		TokenHash:         hash,
		ClientID:          "client-1",
		UserID:            "u-1",
		SessionID:         &sid,
		Scope:             "openid profile email offline_access",
		ExpiresAt:         now.Add(24 * time.Hour),
		AbsoluteExpiresAt: now.Add(24 * time.Hour),
		CreatedAt:         now,
	}); err != nil {
		t.Fatalf("store rt: %v", err)
	}
	return raw
}

func TestRefresh_Handle_RotatesAndMintsNewTokens(t *testing.T) {
	g, rt, _, client := newTestRefresh(t)
	raw := mintRefresh(t, rt, g.Clock, id1())

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", raw)
	form.Set("client_id", "client-1")

	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, client, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Cache-Control"), "no-store") {
		t.Errorf("Cache-Control missing no-store")
	}
	var resp TokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AccessToken == "" {
		t.Errorf("access_token missing")
	}
	if resp.IDToken == "" {
		t.Errorf("id_token missing (openid in scope)")
	}
	if resp.RefreshToken == "" {
		t.Errorf("refresh_token missing — must rotate")
	}
	if resp.RefreshToken == raw {
		t.Errorf("refresh_token must be NEW, got the same value")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", resp.TokenType)
	}
	if !strings.Contains(resp.Scope, "openid") {
		t.Errorf("scope = %q", resp.Scope)
	}

	// Store now contains two tokens, and the old one is consumed.
	all, _ := rt.GetPaged(context.Background(), domain.PagedRequest{Page: 1, PageSize: 10})
	if all.TotalCount != 2 {
		t.Errorf("tokens in store = %d, want 2", all.TotalCount)
	}
	old, _ := rt.FindByHash(context.Background(), token.HashToken(raw))
	if old == nil || old.ConsumedAt == nil {
		t.Errorf("old token not consumed: %+v", old)
	}
	// New token's ParentTokenID points to the old.
	newTok, _ := rt.FindByHash(context.Background(), token.HashToken(resp.RefreshToken))
	if newTok == nil {
		t.Fatalf("new refresh token not in store")
	}
	if newTok.ParentTokenID == nil || *newTok.ParentTokenID != old.ID {
		t.Errorf("ParentTokenID = %v, want %s", newTok.ParentTokenID, old.ID)
	}
}

func TestRefresh_Handle_DetectsReuseAndRevokesChain(t *testing.T) {
	g, rt, auditLogs, client := newTestRefresh(t)
	sid := id1()
	raw := mintRefresh(t, rt, g.Clock, sid)
	mintRefresh(t, rt, g.Clock, sid) // a sibling in the same session chain

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", raw)
	form.Set("client_id", "client-1")

	// First call rotates successfully.
	rr1 := httptest.NewRecorder()
	g.Handle(context.Background(), rr1, client, form)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first: status = %d, want 200; body=%s", rr1.Code, rr1.Body.String())
	}

	// Second call with the same token → reuse.
	rr2 := httptest.NewRecorder()
	g.Handle(context.Background(), rr2, client, form)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("reuse: status = %d, want 400; body=%s", rr2.Code, rr2.Body.String())
	}
	var body ErrorResponse
	_ = json.NewDecoder(rr2.Body).Decode(&body)
	if body.Error != "invalid_grant" {
		t.Errorf("reuse error = %q, want invalid_grant", body.Error)
	}
	if !strings.Contains(strings.ToLower(body.ErrorDescription), "reuse") {
		t.Errorf("error_description = %q, want it to mention reuse", body.ErrorDescription)
	}

	// Every token in the session chain must be revoked.
	all, _ := rt.GetPaged(context.Background(), domain.PagedRequest{Page: 1, PageSize: 10})
	for _, tok := range all.Items {
		if tok.SessionID == nil || *tok.SessionID != sid {
			continue
		}
		if tok.RevokedAt == nil {
			t.Errorf("token %s not revoked after reuse detection", tok.ID)
		}
	}

	// Audit log written.
	logs, _ := auditLogs.GetPaged(context.Background(), domain.PagedRequest{Page: 1, PageSize: 10})
	if logs.TotalCount != 1 {
		t.Fatalf("audit logs = %d, want 1", logs.TotalCount)
	}
	if logs.Items[0].Action != RefreshTokenReuseAudit {
		t.Errorf("audit action = %q, want %q", logs.Items[0].Action, RefreshTokenReuseAudit)
	}
	if logs.Items[0].ActorUserID != "u-1" {
		t.Errorf("audit actor = %q, want u-1", logs.Items[0].ActorUserID)
	}
}

func TestRefresh_Handle_RejectsForeignClient(t *testing.T) {
	g, rt, _, client := newTestRefresh(t)
	raw := mintRefresh(t, rt, g.Clock, id1())

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", raw)
	// form's client_id differs from the authenticated client →
	// the grant's defence-in-depth rejects as invalid_grant.
	form.Set("client_id", "someone-else")

	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, client, form)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var body ErrorResponse
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if body.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", body.Error)
	}
}

func TestRefresh_Handle_RejectsMissingFields(t *testing.T) {
	g, _, _, client := newTestRefresh(t)
	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, client, url.Values{})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var body ErrorResponse
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if body.Error != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", body.Error)
	}
}

func TestRefresh_Handle_RejectsExpiredToken(t *testing.T) {
	g, rt, _, client := newTestRefresh(t)
	raw := mintRefresh(t, rt, g.Clock, id1())

	// Push past the absolute expiry.
	if fc, ok := g.Clock.(*clock.FakeClock); ok {
		fc.Advance(48 * time.Hour)
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", raw)
	form.Set("client_id", "client-1")

	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, client, form)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var body ErrorResponse
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if body.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", body.Error)
	}
}

func TestRefresh_Handle_RejectsRevokedToken(t *testing.T) {
	g, rt, _, client := newTestRefresh(t)
	raw := mintRefresh(t, rt, g.Clock, id1())

	tok, err := rt.FindByHash(context.Background(), token.HashToken(raw))
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if err := rt.Revoke(context.Background(), tok.ID, g.Clock.Now()); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", raw)
	form.Set("client_id", "client-1")

	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, client, form)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var body ErrorResponse
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if body.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", body.Error)
	}
}

func TestRefresh_Handle_RejectsUnknownToken(t *testing.T) {
	g, _, _, client := newTestRefresh(t)
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", "not-a-real-token")
	form.Set("client_id", "client-1")

	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, client, form)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var body ErrorResponse
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if body.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", body.Error)
	}
}

func TestRefresh_Handle_Downscopes(t *testing.T) {
	g, rt, _, client := newTestRefresh(t)
	raw := mintRefresh(t, rt, g.Clock, id1())

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", raw)
	form.Set("client_id", "client-1")
	form.Set("scope", "openid profile") // drop email + offline_access

	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, client, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp TokenResponse
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if strings.Contains(resp.Scope, "email") {
		t.Errorf("down-scoped response still contains email: %q", resp.Scope)
	}
	if resp.RefreshToken != "" {
		t.Errorf("down-scoped response issued a refresh token despite offline_access being dropped")
	}
}

func TestRefresh_Handle_RejectsUpscope(t *testing.T) {
	g, rt, _, client := newTestRefresh(t)
	raw := mintRefresh(t, rt, g.Clock, id1())

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", raw)
	form.Set("client_id", "client-1")
	form.Set("scope", "openid profile email offline_access address phone") // address+phone not granted

	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, client, form)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var body ErrorResponse
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if body.Error != "invalid_scope" {
		t.Errorf("error = %q, want invalid_scope", body.Error)
	}
}

// Ensure the grant conforms to the store.RefreshTokenStore CAS contract:
// MarkConsumed is the only path that flips ConsumedAt.
func TestRefresh_Handle_OnlyOneWinnerOnConcurrentUse(t *testing.T) {
	g, rt, _, client := newTestRefresh(t)
	raw := mintRefresh(t, rt, g.Clock, id1())

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", raw)
	form.Set("client_id", "client-1")

	const N = 8
	type result struct {
		code int
		err  string
	}
	results := make([]result, N)
	done := make(chan struct{}, N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			rr := httptest.NewRecorder()
			g.Handle(context.Background(), rr, client, form)
			var b ErrorResponse
			_ = json.NewDecoder(rr.Body).Decode(&b)
			results[i] = result{code: rr.Code, err: b.Error}
			done <- struct{}{}
		}()
	}
	for i := 0; i < N; i++ {
		<-done
	}
	winners := 0
	losers := 0
	for _, r := range results {
		if r.code == http.StatusOK {
			winners++
		} else if r.code == http.StatusBadRequest && r.err == "invalid_grant" {
			losers++
		} else {
			t.Errorf("unexpected result: code=%d err=%q", r.code, r.err)
		}
	}
	if winners != 1 {
		t.Errorf("winners = %d, want 1", winners)
	}
	if losers != N-1 {
		t.Errorf("losers = %d, want %d", losers, N-1)
	}
}

// stubUserStore lets a test simulate "user no longer exists".
type stubUserStore struct {
	info *domain.UserInfo
	err  error
}

func (s *stubUserStore) ValidateCredentials(context.Context, string, string) (*domain.UserInfo, error) {
	return nil, errors.New("not used")
}
func (s *stubUserStore) FindByID(context.Context, string) (*domain.UserInfo, error) {
	return s.info, s.err
}

// TestRefresh_AuthTime_UsesChainRoot: regression for §1.4 of plan-2.md.
// After several rotations, the ID token's auth_time must equal the
// *root* refresh token's CreatedAt, not the most recently consumed
// token's. Writing the consumed token's CreatedAt as auth_time
// would advance auth_time on every rotation and defeat max_age
// enforcement at the resource server.
func TestRefresh_AuthTime_UsesChainRoot(t *testing.T) {
	g, rt, _, client := newTestRefresh(t)
	raw := mintRefresh(t, rt, g.Clock, id1())

	// Capture the root token's CreatedAt before any rotation.
	root, err := rt.FindByHash(context.Background(), token.HashToken(raw))
	if err != nil {
		t.Fatalf("find root: %v", err)
	}
	rootCreatedAt := root.CreatedAt

	// Advance the clock so each rotation creates a token with a
	// distinct CreatedAt — if the bug were present the ID token
	// would carry the most-recent rotation's time, not the root's.
	fc, ok := g.Clock.(*clock.FakeClock)
	if !ok {
		t.Fatalf("test setup: g.Clock is %T, want *clock.FakeClock", g.Clock)
	}
	fc.Advance(10 * time.Minute)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", raw)
	form.Set("client_id", "client-1")

	rr := httptest.NewRecorder()
	g.Handle(context.Background(), rr, client, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh: status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp TokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.IDToken == "" {
		t.Fatal("id_token missing")
	}

	idTok, err := g.Issuer.VerifyToken(context.Background(), resp.IDToken)
	if err != nil {
		t.Fatalf("VerifyToken(id): %v", err)
	}
	gotAuthTime, _ := idTok.Get("auth_time")
	if gotAuthTime == nil {
		t.Fatal("id_token missing auth_time")
	}
	var gotSec int64
	switch v := gotAuthTime.(type) {
	case float64:
		gotSec = int64(v)
	case int64:
		gotSec = v
	case json.Number:
		gotSec, _ = v.Int64()
	default:
		t.Fatalf("auth_time has unexpected type %T", gotAuthTime)
	}
	wantSec := rootCreatedAt.Unix()
	if gotSec != wantSec {
		t.Errorf("auth_time = %d (%s), want %d (chain root CreatedAt = %s)", gotSec, time.Unix(gotSec, 0).UTC(), wantSec, rootCreatedAt)
	}

	// And the access token carries the same auth_time. The grant
	// passes AuthTime into both the access and ID token issuance
	// paths; assert both stay in sync.
	accessTok, err := g.Issuer.VerifyToken(context.Background(), resp.AccessToken)
	if err != nil {
		t.Fatalf("VerifyToken(access): %v", err)
	}
	gotAccessAuth, _ := accessTok.Get("auth_time")
	if gotAccessAuth == nil {
		t.Fatal("access token missing auth_time")
	}
	var gotAccessSec int64
	switch v := gotAccessAuth.(type) {
	case float64:
		gotAccessSec = int64(v)
	case int64:
		gotAccessSec = v
	case json.Number:
		gotAccessSec, _ = v.Int64()
	default:
		t.Fatalf("access auth_time has unexpected type %T", gotAccessAuth)
	}
	if gotAccessSec != wantSec {
		t.Errorf("access auth_time = %d, want %d (chain root)", gotAccessSec, wantSec)
	}
}

// keep the store import alive for the linter
var _ = store.ErrNotFound
