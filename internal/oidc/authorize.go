package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/session"
	"go-authserver/internal/store"
	"go-authserver/internal/token"

	"github.com/google/uuid"
)

// AuthorizeConfig bundles policy inputs the authorize handler reads.
type AuthorizeConfig struct {
	IssuerURL        string
	LoginPath        string
	AuthorizePath    string
	AuthCodeLifetime time.Duration
	RequirePKCE      bool
	// MaxSessionAge is compared against session.CreatedAt to enforce
	// max_age. Optional.
	MaxSessionAge time.Duration
}

// AuthorizeHandler implements GET /connect/authorize.
type AuthorizeHandler struct {
	Cfg       AuthorizeConfig
	Clients   store.ClientStore
	AuthCodes store.AuthorizationCodeStore
	Sessions  store.SessionStore
	Users     store.UserStore
	Cookies   *session.CookieManager
	Issuer    *token.Issuer
	Clock     clock.Clock
	Logger    *slog.Logger
}

func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	scope := q.Get("scope")
	state := q.Get("state")
	nonce := q.Get("nonce")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	prompt := q.Get("prompt")
	maxAgeRaw := q.Get("max_age")

	// 1. Unknown client → HTML/JSON error, no redirect.
	if clientID == "" {
		writeAuthorizeError(w, "", ErrInvalidRequest, "client_id is required", state, http.StatusBadRequest)
		return
	}
	client, err := h.Clients.FindByClientID(r.Context(), clientID)
	if err != nil {
		writeAuthorizeError(w, "", ErrInvalidRequest, "unknown client", state, http.StatusBadRequest)
		return
	}

	// 2. redirect_uri FIRST (RFC 6749 §4.1.2.1). Exact match — no prefix,
	// no wildcard. Any failure here returns an error WITHOUT redirecting.
	if !slices.Contains(client.RedirectURIs, redirectURI) {
		writeAuthorizeError(w, "", ErrInvalidRequest, "redirect_uri not registered", state, http.StatusBadRequest)
		return
	}

	// 3. From here on, every error is a 302-redirect back to the validated
	// redirect_uri.
	redirectErr := func(code, desc string) {
		target := redirectError(redirectURI, code, desc, state)
		http.Redirect(w, r, target, http.StatusFound)
	}

	if responseType != "code" {
		redirectErr(ErrUnsupportedGrantType, "only response_type=code is supported")
		return
	}
	if !scopesAllowed(scope, client.AllowedScopes) {
		redirectErr(ErrInvalidScope, "scope is not allowed for this client")
		return
	}

	// 4. PKCE
	if client.RequirePKCE || h.Cfg.RequirePKCE {
		if codeChallenge == "" {
			redirectErr(ErrInvalidRequest, "code_challenge is required")
			return
		}
		if codeChallengeMethod != token.PKCEMethod {
			redirectErr(ErrInvalidRequest, "code_challenge_method must be S256")
			return
		}
	}

	// 5. max_age parsing (optional).
	var maxAge time.Duration
	if maxAgeRaw != "" {
		secs, err := strconv.Atoi(maxAgeRaw)
		if err != nil || secs < 0 {
			redirectErr(ErrInvalidRequest, "max_age must be a non-negative integer")
			return
		}
		maxAge = time.Duration(secs) * time.Second
	}

	// 6. Session resolve.
	sess, err := h.resolveSession(r)
	if err != nil && !errors.Is(err, session.ErrNoSession) {
		h.Logger.Error("session resolve failed", "err", err)
		redirectErr(ErrServerError, "session lookup failed")
		return
	}

	if prompt == "none" {
		if sess == nil || sess.RevokedAt != nil || h.Clock.Now().After(sess.ExpiresAt) {
			redirectErr(ErrLoginRequired, "login required")
			return
		}
	} else if prompt == "login" {
		sess = nil
	} else if sess != nil && maxAge > 0 {
		if h.Clock.Now().Sub(sess.CreatedAt) > maxAge {
			sess = nil
		}
	}

	if sess == nil {
		// 7. No session → bounce to login with returnUrl.
		target := h.Cfg.LoginPath + "?returnUrl=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	// 8. User resolve for ID token claims.
	info, err := h.Users.FindByID(r.Context(), sess.UserID)
	if err != nil {
		h.Logger.Error("user lookup failed", "err", err)
		redirectErr(ErrServerError, "user lookup failed")
		return
	}

	// 9. Mint auth code.
	code, err := h.mintCode(r.Context(), client, sess, info, redirectURI, scope, nonce, codeChallenge, codeChallengeMethod)
	if err != nil {
		h.Logger.Error("auth code mint failed", "err", err)
		redirectErr(ErrServerError, "could not mint code")
		return
	}

	// 10. 302 to redirect_uri?code=...&state=...
	target, err := buildAuthorizeRedirect(redirectURI, code, state)
	if err != nil {
		redirectErr(ErrServerError, "could not build redirect")
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (h *AuthorizeHandler) resolveSession(r *http.Request) (*domain.Session, error) {
	id, err := h.Cookies.FromRequest(r)
	if err != nil {
		return nil, err
	}
	sess, err := h.Sessions.Find(r.Context(), id)
	if err != nil {
		return nil, err
	}
	if sess.RevokedAt != nil || h.Clock.Now().After(sess.ExpiresAt) {
		return nil, nil
	}
	return sess, nil
}

func (h *AuthorizeHandler) mintCode(
	ctx context.Context,
	client *domain.Client,
	sess *domain.Session,
	_ *domain.UserInfo,
	redirectURI, scope, nonce, challenge, method string,
) (string, error) {
	raw, hash, err := token.NewOpaqueToken()
	if err != nil {
		return "", fmt.Errorf("auth code opaque: %w", err)
	}
	now := h.Clock.Now().UTC()
	sid := sess.ID
	code := &domain.AuthorizationCode{
		ID:                  uuid.New(),
		CodeHash:            hash,
		ClientID:            client.ClientID,
		UserID:              sess.UserID,
		SessionID:           &sid,
		RedirectURI:         redirectURI,
		CodeChallenge:       stringPtr(challenge),
		CodeChallengeMethod: stringPtr(method),
		Scope:               scope,
		Nonce:               stringPtr(nonce),
		ExpiresAt:           now.Add(h.Cfg.AuthCodeLifetime),
		CreatedAt:           now,
	}
	if challenge == "" {
		code.CodeChallenge = nil
		code.CodeChallengeMethod = nil
	}
	if nonce == "" {
		code.Nonce = nil
	}
	if err := h.AuthCodes.Store(ctx, code); err != nil {
		return "", fmt.Errorf("auth code store: %w", err)
	}
	return raw, nil
}

func buildAuthorizeRedirect(redirectURI, code, state string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func scopesAllowed(scope string, allowed []string) bool {
	if scope == "" {
		// An empty scope is a degenerate request; reject.
		return false
	}
	for _, s := range strings.Fields(scope) {
		if !slices.Contains(allowed, s) {
			return false
		}
	}
	return true
}

func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// writeAuthorizeError is used for the pre-validation errors that must not
// redirect to an unvalidated URI.
func writeAuthorizeError(w http.ResponseWriter, _, code, desc, _ string, status int) {
	writeJSONError(w, status, code, desc)
}
