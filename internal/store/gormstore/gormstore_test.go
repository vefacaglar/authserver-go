package gormstore

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// openTestDB returns a fresh SQLite-backed *gorm.DB on disk so the
// WAL-mode concurrency is exercised. The file is removed via
// t.Cleanup.
func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dir := t.TempDir()
	dsn := filepath.Join(dir, "test.db") + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"
	db, err := Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestMigrate_CreatesAllTables(t *testing.T) {
	db := openTestDB(t)
	for _, name := range []string{
		"oauth_clients",
		"oauth_authorization_codes",
		"oauth_refresh_tokens",
		"oauth_sessions",
		"oauth_signing_keys",
		"oauth_scopes",
		"oauth_users",
		"oauth_audit_logs",
		"oauth_password_reset_tokens",
	} {
		if !db.Migrator().HasTable(name) {
			t.Errorf("table %q not created", name)
		}
	}
}

func TestMigrate_Idempotent(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Errorf("second Migrate: %v", err)
	}
}

func TestMigrate_OpenBadDriverErrors(t *testing.T) {
	_, err := Open("oracle", "x")
	if err == nil {
		t.Fatalf("expected error for unsupported driver")
	}
}

func TestMigrate_OpenEmptyDSNErrors(t *testing.T) {
	_, err := Open("sqlite", "")
	if err == nil {
		t.Fatalf("expected error for empty DSN")
	}
}

// --- ClientStore ---

func TestClient_StoreAndFind(t *testing.T) {
	db := openTestDB(t)
	s := NewClientStore(db)
	c := &domain.Client{
		ClientID:                "client-1",
		DisplayName:             "Test",
		RedirectURIs:            []string{"https://app.example/cb", "https://app.example/cb2"},
		PostLogoutRedirectURIs:  []string{"https://app.example/"},
		AllowedScopes:           []string{"openid", "profile"},
		RequirePKCE:             true,
		AllowRefreshTokens:      true,
		TokenEndpointAuthMethod: domain.TokenEndpointAuthMethodNone,
		Properties:              map[string]string{"team": "auth"},
	}
	if err := s.Store(context.Background(), c); err != nil {
		t.Fatalf("store: %v", err)
	}
	got, err := s.FindByClientID(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.DisplayName != "Test" {
		t.Errorf("display name = %q", got.DisplayName)
	}
	if len(got.RedirectURIs) != 2 {
		t.Errorf("redirect_uris len = %d, want 2", len(got.RedirectURIs))
	}
	if got.Properties["team"] != "auth" {
		t.Errorf("properties[team] = %q", got.Properties["team"])
	}
}

func TestClient_OverwriteRoundTrip(t *testing.T) {
	db := openTestDB(t)
	s := NewClientStore(db)
	c := &domain.Client{ClientID: "client-1", DisplayName: "v1", AllowedScopes: []string{"openid"}}
	if err := s.Store(context.Background(), c); err != nil {
		t.Fatalf("store v1: %v", err)
	}
	c.DisplayName = "v2"
	if err := s.Store(context.Background(), c); err != nil {
		t.Fatalf("store v2: %v", err)
	}
	got, _ := s.FindByClientID(context.Background(), "client-1")
	if got.DisplayName != "v2" {
		t.Errorf("after overwrite display name = %q, want v2", got.DisplayName)
	}
}

func TestClient_Delete(t *testing.T) {
	db := openTestDB(t)
	s := NewClientStore(db)
	_ = s.Store(context.Background(), &domain.Client{ClientID: "client-1"})
	if err := s.Delete(context.Background(), "client-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.FindByClientID(context.Background(), "client-1"); err == nil {
		t.Errorf("expected ErrNotFound after delete")
	}
	if err := s.Delete(context.Background(), "client-1"); err == nil {
		t.Errorf("delete on missing row should error")
	}
}

func TestClient_GetPaged(t *testing.T) {
	db := openTestDB(t)
	s := NewClientStore(db)
	for _, id := range []string{"c-a", "c-b", "c-c"} {
		_ = s.Store(context.Background(), &domain.Client{ClientID: id})
	}
	res, err := s.GetPaged(context.Background(), domain.PagedRequest{Page: 1, PageSize: 2})
	if err != nil {
		t.Fatalf("paged: %v", err)
	}
	if res.TotalCount != 3 {
		t.Errorf("total = %d, want 3", res.TotalCount)
	}
	if len(res.Items) != 2 {
		t.Errorf("page items = %d, want 2", len(res.Items))
	}
}

// --- AuthorizationCodeStore ---

func mintAuthCode(t *testing.T, s *AuthorizationCodeStore, hash string, exp time.Time) *domain.AuthorizationCode {
	t.Helper()
	now := time.Now().UTC()
	c := &domain.AuthorizationCode{
		ID:          uuid.New(),
		CodeHash:    hash,
		ClientID:    "client-1",
		UserID:      "u-1",
		RedirectURI: "https://app.example/cb",
		Scope:       "openid",
		ExpiresAt:   exp,
		CreatedAt:   now,
	}
	if err := s.Store(context.Background(), c); err != nil {
		t.Fatalf("store auth code: %v", err)
	}
	return c
}

func TestAuthCode_FindByHash(t *testing.T) {
	db := openTestDB(t)
	s := NewAuthorizationCodeStore(db)
	c := mintAuthCode(t, s, "hash-1", time.Now().Add(time.Minute))
	got, err := s.FindByHash(context.Background(), "hash-1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.ID != c.ID {
		t.Errorf("id = %s, want %s", got.ID, c.ID)
	}
}

func TestAuthCode_MarkConsumedExactlyOneWinner(t *testing.T) {
	db := openTestDB(t)
	s := NewAuthorizationCodeStore(db)
	c := mintAuthCode(t, s, "hash-1", time.Now().Add(time.Minute))

	const N = 16
	results := make([]bool, N)
	errs := make([]error, N)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			won, err := s.MarkConsumed(context.Background(), c.ID, time.Now().UTC())
			results[i] = won
			errs[i] = err
		}()
	}
	wg.Wait()

	winners := 0
	for i, won := range results {
		if errs[i] != nil {
			t.Errorf("goroutine %d: err = %v", i, errs[i])
		}
		if won {
			winners++
		}
	}
	if winners != 1 {
		t.Errorf("winners = %d, want 1", winners)
	}

	// Re-fetching shows ConsumedAt set.
	got, _ := s.FindByHash(context.Background(), "hash-1")
	if got.ConsumedAt == nil {
		t.Errorf("ConsumedAt not set after CAS")
	}
}

func TestAuthCode_MarkConsumedUnknownIDReturnsFalse(t *testing.T) {
	db := openTestDB(t)
	s := NewAuthorizationCodeStore(db)
	won, err := s.MarkConsumed(context.Background(), uuid.New(), time.Now().UTC())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if won {
		t.Errorf("won = true, want false for unknown id")
	}
}

// --- RefreshTokenStore ---

func mintRefresh(t *testing.T, s *RefreshTokenStore, hash string, sessionID uuid.UUID) *domain.RefreshToken {
	t.Helper()
	now := time.Now().UTC()
	rt := &domain.RefreshToken{
		ID:                uuid.New(),
		TokenHash:         hash,
		ClientID:          "client-1",
		UserID:            "u-1",
		SessionID:         &sessionID,
		Scope:             "openid offline_access",
		ExpiresAt:         now.Add(time.Hour),
		AbsoluteExpiresAt: now.Add(24 * time.Hour),
		CreatedAt:         now,
	}
	if err := s.Store(context.Background(), rt); err != nil {
		t.Fatalf("store rt: %v", err)
	}
	return rt
}

func TestRefresh_FindByHash(t *testing.T) {
	db := openTestDB(t)
	s := NewRefreshTokenStore(db)
	rt := mintRefresh(t, s, "h-1", uuid.New())
	got, err := s.FindByHash(context.Background(), "h-1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.ID != rt.ID {
		t.Errorf("id = %s, want %s", got.ID, rt.ID)
	}
	if got.SessionID == nil || *got.SessionID != *rt.SessionID {
		t.Errorf("session_id = %v, want %v", got.SessionID, rt.SessionID)
	}
}

func TestRefresh_MarkConsumedExactlyOneWinner(t *testing.T) {
	db := openTestDB(t)
	s := NewRefreshTokenStore(db)
	rt := mintRefresh(t, s, "h-1", uuid.New())

	const N = 16
	results := make([]bool, N)
	errs := make([]error, N)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			won, err := s.MarkConsumed(context.Background(), rt.ID, time.Now().UTC())
			results[i] = won
			errs[i] = err
		}()
	}
	wg.Wait()
	winners := 0
	for i, won := range results {
		if errs[i] != nil {
			t.Errorf("goroutine %d: err = %v", i, errs[i])
		}
		if won {
			winners++
		}
	}
	if winners != 1 {
		t.Errorf("winners = %d, want 1", winners)
	}
}

func TestRefresh_RevokeBySessionID(t *testing.T) {
	db := openTestDB(t)
	s := NewRefreshTokenStore(db)
	sid := uuid.New()
	rt1 := mintRefresh(t, s, "h-1", sid)
	rt2 := mintRefresh(t, s, "h-2", sid)
	mintRefresh(t, s, "h-3", uuid.New()) // different session

	now := time.Now().UTC()
	if err := s.RevokeBySessionID(context.Background(), sid, now); err != nil {
		t.Fatalf("revoke by session: %v", err)
	}
	for _, hash := range []string{"h-1", "h-2", "h-3"} {
		rt, _ := s.FindByHash(context.Background(), hash)
		if hash == "h-3" {
			if rt.RevokedAt != nil {
				t.Errorf("h-3 in different session was revoked: %+v", rt)
			}
		} else {
			if rt.RevokedAt == nil {
				t.Errorf("%s not revoked; rt=%+v", hash, rt)
			}
		}
	}
	_ = rt1
	_ = rt2
}

func TestRefresh_RevokeIdempotent(t *testing.T) {
	db := openTestDB(t)
	s := NewRefreshTokenStore(db)
	rt := mintRefresh(t, s, "h-1", uuid.New())
	now := time.Now().UTC()
	if err := s.Revoke(context.Background(), rt.ID, now); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if err := s.Revoke(context.Background(), rt.ID, now); err != nil {
		t.Errorf("second revoke: %v (idempotent expected)", err)
	}
}

func TestRefresh_GetPaged(t *testing.T) {
	db := openTestDB(t)
	s := NewRefreshTokenStore(db)
	for i := 0; i < 5; i++ {
		mintRefresh(t, s, "h-"+string(rune('a'+i)), uuid.New())
	}
	res, err := s.GetPaged(context.Background(), domain.PagedRequest{Page: 1, PageSize: 3})
	if err != nil {
		t.Fatalf("paged: %v", err)
	}
	if res.TotalCount != 5 {
		t.Errorf("total = %d, want 5", res.TotalCount)
	}
	if len(res.Items) != 3 {
		t.Errorf("page items = %d, want 3", len(res.Items))
	}
}

// --- SessionStore ---

func TestSession_RoundTrip(t *testing.T) {
	db := openTestDB(t)
	s := NewSessionStore(db)
	sess := &domain.Session{
		ID:         uuid.New(),
		UserID:     "u-1",
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  time.Now().Add(time.Hour),
		Properties: map[string]string{"device": "ios"},
	}
	if err := s.Store(context.Background(), sess); err != nil {
		t.Fatalf("store: %v", err)
	}
	got, err := s.Find(context.Background(), sess.ID)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.Properties["device"] != "ios" {
		t.Errorf("properties lost: %+v", got.Properties)
	}
}

func TestSession_Revoke(t *testing.T) {
	db := openTestDB(t)
	s := NewSessionStore(db)
	sess := &domain.Session{
		ID:        uuid.New(),
		UserID:    "u-1",
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = s.Store(context.Background(), sess)
	if err := s.Revoke(context.Background(), sess.ID, time.Now().UTC()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, _ := s.Find(context.Background(), sess.ID)
	if got.RevokedAt == nil {
		t.Errorf("RevokedAt not set")
	}
}

// --- SigningKeyStore ---

func TestSigningKey_GetActiveAndGetAll(t *testing.T) {
	db := openTestDB(t)
	s := NewSigningKeyStore(db)
	now := time.Now().UTC()
	_ = s.Store(context.Background(), &domain.SigningKey{KeyID: "k1", Algorithm: "RS256", IsActive: false, CreatedAt: now})
	_ = s.Store(context.Background(), &domain.SigningKey{KeyID: "k2", Algorithm: "RS256", IsActive: true, CreatedAt: now})
	_ = s.Store(context.Background(), &domain.SigningKey{KeyID: "k3", Algorithm: "RS256", IsActive: false, CreatedAt: now})

	active, err := s.GetActive(context.Background())
	if err != nil {
		t.Fatalf("get active: %v", err)
	}
	if active.KeyID != "k2" {
		t.Errorf("active = %q, want k2", active.KeyID)
	}
	all, _ := s.GetAll(context.Background())
	if len(all) != 3 {
		t.Errorf("len(all) = %d, want 3", len(all))
	}
}

// --- ScopeStore ---

func TestScope_RoundTrip(t *testing.T) {
	db := openTestDB(t)
	s := NewScopeStore(db)
	_ = s.Store(context.Background(), &domain.Scope{Name: "openid", DisplayName: "OpenID", Required: true, Properties: map[string]string{"icon": "key"}})
	_ = s.Store(context.Background(), &domain.Scope{Name: "profile"})

	all, _ := s.GetAll(context.Background())
	if len(all) != 2 {
		t.Errorf("len(all) = %d, want 2", len(all))
	}
	got, err := s.FindByName(context.Background(), "openid")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if !got.Required {
		t.Errorf("Required = false, want true")
	}
	if got.Properties["icon"] != "key" {
		t.Errorf("properties lost: %+v", got.Properties)
	}
	if err := s.Delete(context.Background(), "openid"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.FindByName(context.Background(), "openid"); err == nil {
		t.Errorf("expected ErrNotFound after delete")
	}
}

// --- UserStore ---

func TestUser_ValidateAndFind(t *testing.T) {
	db := openTestDB(t)
	s := NewUserStore(db)
	now := time.Now().UTC()
	user := &domain.User{
		ID:        "u-1",
		Username:  "alice",
		Email:     "alice@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.CreateUser(context.Background(), user, "secret"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.AddUserClaims(context.Background(), "u-1", []domain.UserClaim{
		{Type: "preferred_username", Value: "alice"},
		{Type: "email", Value: "alice@example.com"},
	}); err != nil {
		t.Fatalf("add claims: %v", err)
	}

	got, err := s.ValidateCredentials(context.Background(), "alice", "wrong")
	if err != nil {
		t.Fatalf("wrong: err = %v", err)
	}
	if got != nil {
		t.Errorf("wrong creds returned user: %+v", got)
	}

	got, err = s.ValidateCredentials(context.Background(), "alice", "secret")
	if err != nil {
		t.Fatalf("right: %v", err)
	}
	if got == nil || got.UserID != "u-1" {
		t.Errorf("right creds returned %+v", got)
	}

	got, err = s.ValidateCredentials(context.Background(), "ghost", "secret")
	if err != nil {
		t.Fatalf("ghost: err = %v", err)
	}
	if got != nil {
		t.Errorf("ghost returned user: %+v", got)
	}

	found, err := s.FindByID(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if found.Claims["email"] != "alice@example.com" {
		t.Errorf("claims lost: %+v", found.Claims)
	}
}

func TestUser_CreateDuplicate(t *testing.T) {
	db := openTestDB(t)
	s := NewUserStore(db)
	now := time.Now().UTC()
	user := &domain.User{
		ID:        "u-1",
		Username:  "alice",
		Email:     "alice@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.CreateUser(context.Background(), user, "secret"); err != nil {
		t.Fatalf("first create failed: %v", err)
	}
	err := s.CreateUser(context.Background(), user, "secret")
	if err == nil {
		t.Fatal("expected error on duplicate user create, got nil")
	}
	if !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("expected store.ErrDuplicate, got: %v", err)
	}
}

func TestRole_CreateDuplicate(t *testing.T) {
	db := openTestDB(t)
	s := NewRoleStore(db)
	role := &domain.Role{
		ID:   "role-1",
		Name: "admin",
	}
	if err := s.CreateRole(context.Background(), role); err != nil {
		t.Fatalf("first create failed: %v", err)
	}
	err := s.CreateRole(context.Background(), role)
	if err == nil {
		t.Fatal("expected error on duplicate role create, got nil")
	}
	if !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("expected store.ErrDuplicate, got: %v", err)
	}
}

// --- AuditLogStore ---

func TestAuditLog_StoreAndPage(t *testing.T) {
	db := openTestDB(t)
	s := NewAuditLogStore(db)
	for i := 0; i < 7; i++ {
		_ = s.Store(context.Background(), &domain.AuditLog{
			ID:          uuid.New(),
			Action:      "Test",
			ActorUserID: "u-1",
			Timestamp:   time.Now().UTC(),
		})
	}
	res, _ := s.GetPaged(context.Background(), domain.PagedRequest{Page: 1, PageSize: 3})
	if res.TotalCount != 7 {
		t.Errorf("total = %d, want 7", res.TotalCount)
	}
	if len(res.Items) != 3 {
		t.Errorf("page items = %d, want 3", len(res.Items))
	}
}

func TestSession_ListAndRevokeByUserID(t *testing.T) {
	ctx := context.Background()
	s := NewSessionStore(openTestDB(t))
	now := time.Unix(1700000000, 0).UTC()

	mk := func(userID string, created time.Time, ttl time.Duration) uuid.UUID {
		id := uuid.New()
		if err := s.Store(ctx, &domain.Session{ID: id, UserID: userID, CreatedAt: created, ExpiresAt: created.Add(ttl)}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	keep := mk("u-1", now.Add(-time.Hour), 8*time.Hour)
	other := mk("u-1", now.Add(-2*time.Hour), 8*time.Hour)
	mk("u-1", now.Add(-10*time.Hour), time.Hour) // expired
	foreign := mk("u-2", now, time.Hour)

	list, err := s.ListByUserID(ctx, "u-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != keep || list[1].ID != other {
		t.Fatalf("ListByUserID = %+v, want [keep, other]", list)
	}

	revoked, err := s.RevokeByUserIDExcept(ctx, "u-1", keep, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 1 || revoked[0] != other {
		t.Fatalf("revoked = %v, want [%s]", revoked, other)
	}
	for id, want := range map[uuid.UUID]bool{keep: false, other: true, foreign: false} {
		sess, err := s.Find(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if (sess.RevokedAt != nil) != want {
			t.Errorf("session %s revoked=%v, want %v", id, sess.RevokedAt != nil, want)
		}
	}
	again, err := s.RevokeByUserIDExcept(ctx, "u-1", keep, now)
	if err != nil || len(again) != 0 {
		t.Fatalf("second call = %v, %v; want empty", again, err)
	}
}

func TestAuditLog_ListByActor(t *testing.T) {
	ctx := context.Background()
	s := NewAuditLogStore(openTestDB(t))
	base := time.Unix(1700000000, 0).UTC()
	add := func(actor, action string, offset time.Duration) {
		if err := s.Store(ctx, &domain.AuditLog{ID: uuid.New(), Action: action, ActorUserID: actor, Timestamp: base.Add(offset)}); err != nil {
			t.Fatal(err)
		}
	}
	add("u-1", domain.AuditLoginSucceeded, 0)
	add("u-1", domain.AuditLoginSucceeded, 2*time.Minute)
	add("u-1", domain.AuditLoginSucceeded, time.Minute)
	add("u-1", "other_action", 5*time.Minute)
	add("u-2", domain.AuditLoginSucceeded, 9*time.Minute)

	got, err := s.ListByActor(ctx, "u-1", domain.AuditLoginSucceeded, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0].Timestamp.Equal(base.Add(2*time.Minute)) || !got[1].Timestamp.Equal(base.Add(time.Minute)) {
		t.Fatalf("ListByActor = %+v, want the two newest u-1 logins, newest first", got)
	}
}

func TestPasswordReset_GORM(t *testing.T) {
	ctx := context.Background()
	s := NewPasswordResetStore(openTestDB(t))
	now := time.Unix(1700000000, 0).UTC()
	mk := func(user, hash string, at time.Time, ttl time.Duration) *domain.PasswordResetToken {
		tk := &domain.PasswordResetToken{ID: uuid.New(), UserID: user, TokenHash: hash, CreatedAt: at, ExpiresAt: at.Add(ttl)}
		if err := s.Create(ctx, tk); err != nil {
			t.Fatal(err)
		}
		return tk
	}

	tok := mk("u-1", "hash-1", now, time.Hour)
	got, err := s.FindByHash(ctx, "hash-1")
	if err != nil || got.ID != tok.ID || got.ConsumedAt != nil {
		t.Fatalf("FindByHash = %+v, %v", got, err)
	}
	if _, err := s.FindByHash(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("missing err = %v, want ErrNotFound", err)
	}
	if err := s.Create(ctx, &domain.PasswordResetToken{ID: uuid.New(), UserID: "u-2", TokenHash: "hash-1", ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("duplicate hash err = %v, want ErrDuplicate", err)
	}

	// Concurrent consumers: exactly one wins.
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.Consume(ctx, tok.ID, now)
			if err != nil {
				t.Error(err)
				return
			}
			if ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("winners = %d, want exactly 1", wins)
	}

	expiring := mk("u-3", "hash-exp", now, time.Minute)
	if ok, _ := s.Consume(ctx, expiring.ID, now.Add(time.Minute)); ok {
		t.Error("expired token consumed")
	}

	a := mk("u-4", "hash-a", now, time.Hour)
	other := mk("u-5", "hash-o", now, time.Hour)
	if err := s.InvalidateForUser(ctx, "u-4", now); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Consume(ctx, a.ID, now); ok {
		t.Error("token consumable after InvalidateForUser")
	}
	if ok, _ := s.Consume(ctx, other.ID, now); !ok {
		t.Error("another user's token was invalidated")
	}

	old := mk("u-6", "hash-old", now.Add(-48*time.Hour), time.Hour)
	n, err := s.DeleteExpired(ctx, now.Add(-24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("DeleteExpired = %d, %v; want 1", n, err)
	}
	if _, err := s.FindByHash(ctx, old.TokenHash); !errors.Is(err, store.ErrNotFound) {
		t.Error("expired token not deleted")
	}
}
