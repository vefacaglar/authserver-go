package oidc

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/store"

	"github.com/google/uuid"
)

// Register flow error codes.
const (
	RegisterErrMissingFields      = "missing_fields"
	RegisterErrPasswordMismatch   = "password_mismatch"
	RegisterErrDuplicateUser      = "duplicate_user"
	RegisterErrAntiforgeryFailed  = "antiforgery_failed"
	RegisterErrServerError        = "server_error"
)

type RegisterConfig struct {
	RegisterPath string
	LoginPath    string
	IssuerURL    string
}

type RegisterHandler struct {
	Cfg      RegisterConfig
	Users    store.UserStore
	Clock    clock.Clock
	Logger   *slog.Logger
	Template *template.Template
}

func (h *RegisterHandler) issueCSRFToken(w http.ResponseWriter, r *http.Request) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		h.Logger.Error("csrf rand", "err", err)
		return ""
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	cookie := &http.Cookie{
		Name:     csrfCookieName,
		Value:    tok,
		Path:     h.Cfg.RegisterPath,
		HttpOnly: true,
		Secure:   strings.HasPrefix(h.Cfg.IssuerURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
	return tok
}

func (h *RegisterHandler) verifyCSRFToken(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return false
	}
	got := r.FormValue(csrfFieldName)
	if got == "" {
		got = r.Header.Get(csrfHeaderName)
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(got)) == 1
}

func (h *RegisterHandler) render(w http.ResponseWriter, r *http.Request, errorCode string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	token := h.issueCSRFToken(w, r)
	data := struct {
		CSRFToken  string
		Action     string
		LoginPath  string
		Error      string
		ErrorLabel string
	}{
		CSRFToken: token,
		Action:    h.Cfg.RegisterPath,
		LoginPath: h.Cfg.LoginPath,
		Error:     errorCode,
	}
	if errorCode != "" {
		data.ErrorLabel = registerErrorLabel(errorCode)
	}
	if err := h.Template.Execute(w, data); err != nil {
		h.Logger.Error("register render failed", "err", err)
	}
}

func (h *RegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.render(w, r, r.URL.Query().Get("error"))
	case http.MethodPost:
		h.handlePost(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeJSONError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
	}
}

func (h *RegisterHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		h.respondWithError(w, r, RegisterErrMissingFields)
		return
	}
	if !h.verifyCSRFToken(r) {
		h.respondWithError(w, r, RegisterErrAntiforgeryFailed)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	passwordConfirm := r.FormValue("password_confirm")

	if username == "" || email == "" || password == "" || passwordConfirm == "" {
		h.respondWithError(w, r, RegisterErrMissingFields)
		return
	}

	if password != passwordConfirm {
		h.respondWithError(w, r, RegisterErrPasswordMismatch)
		return
	}

	now := h.Clock.Now().UTC()
	user := &domain.User{
		ID:             uuid.New().String(),
		Username:       username,
		Email:          email,
		EmailConfirmed: false,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	err := h.Users.CreateUser(ctx, user, password)
	if err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			h.respondWithError(w, r, RegisterErrDuplicateUser)
			return
		}
		h.Logger.Error("user store error during registration", "err", err)
		h.respondWithError(w, r, RegisterErrServerError)
		return
	}

	// Successfully registered. Redirect to login page.
	http.Redirect(w, r, h.Cfg.LoginPath, http.StatusFound)
}

func (h *RegisterHandler) respondWithError(w http.ResponseWriter, r *http.Request, code string) {
	q := url.Values{}
	q.Set("error", code)
	target := h.Cfg.RegisterPath + "?" + q.Encode()
	http.Redirect(w, r, target, http.StatusFound)
}

func registerErrorLabel(code string) string {
	switch code {
	case RegisterErrMissingFields:
		return "Please fill out all fields."
	case RegisterErrPasswordMismatch:
		return "Passwords do not match."
	case RegisterErrDuplicateUser:
		return "Username or email is already taken."
	case RegisterErrAntiforgeryFailed:
		return "Your session expired. Please reload and try again."
	case RegisterErrServerError:
		return "An unexpected error occurred. Please try again later."
	default:
		return "An unexpected error occurred."
	}
}
