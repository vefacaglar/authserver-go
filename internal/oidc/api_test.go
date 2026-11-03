package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go-authserver/internal/domain"
	"go-authserver/internal/store/memory"

	"github.com/google/uuid"
)

func TestCSRFHandler_IssuesTokenAcceptedByGuard(t *testing.T) {
	h := &CSRFHandler{}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/csrf", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.CSRFToken == "" {
		t.Fatalf("body = %q, err = %v", rec.Body.String(), err)
	}
	cookie := findCookie(rec.Result().Cookies(), csrfCookieName)
	if cookie == nil {
		t.Fatal("csrf cookie not set")
	}
	if cookie.Path != "/" || !cookie.HttpOnly {
		t.Errorf("cookie attrs: path=%q httponly=%v, want / + HttpOnly", cookie.Path, cookie.HttpOnly)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.AddCookie(cookie)
	req.Header.Set(csrfHeaderName, body.CSRFToken)
	if !APICSRFGuard(false).VerifyHeader(req) {
		t.Error("issued token rejected by guard")
	}
	req.Header.Set(csrfHeaderName, "wrong")
	if APICSRFGuard(false).VerifyHeader(req) {
		t.Error("wrong token accepted by guard")
	}
}

func TestSessionHandler_Anonymous(t *testing.T) {
	res, _, _ := newTestResolver(t)
	h := &SessionHandler{Resolver: res, Users: memory.NewUserStore(), AdminRole: "admin"}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/session", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body sessionView
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Authenticated || body.IsAdmin {
		t.Errorf("body = %+v, want unauthenticated", body)
	}
}

func TestSessionHandler_ReportsRolesAndAdmin(t *testing.T) {
	res, sessions, clk := newTestResolver(t)
	users := memory.NewUserStore()
	now := clk.Now()
	for _, u := range []domain.User{
		{ID: "u-admin", Username: "root", Email: "root@example.com", CreatedAt: now, UpdatedAt: now},
		{ID: "u-plain", Username: "bob", Email: "bob@example.com", CreatedAt: now, UpdatedAt: now},
	} {
		u := u
		if err := users.CreateUser(context.Background(), &u, "pw"); err != nil {
			t.Fatal(err)
		}
	}
	if err := users.AddToRoles(context.Background(), "u-admin", []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	h := &SessionHandler{Resolver: res, Users: users, AdminRole: "admin"}

	for _, tc := range []struct {
		userID   string
		username string
		isAdmin  bool
	}{
		{"u-admin", "root", true},
		{"u-plain", "bob", false},
	} {
		sess := &domain.Session{ID: uuid.New(), UserID: tc.userID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		if err := sessions.Store(context.Background(), sess); err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, requestWithSession(t, res, sess.ID))
		var body sessionView
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if !body.Authenticated || body.Username != tc.username || body.IsAdmin != tc.isAdmin {
			t.Errorf("user %s: body = %+v, want username=%s is_admin=%v", tc.userID, body, tc.username, tc.isAdmin)
		}
	}
}
