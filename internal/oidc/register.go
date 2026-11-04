package oidc

import (
	"errors"
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
	RegisterErrMissingFields     = "missing_fields"
	RegisterErrPasswordMismatch  = "password_mismatch"
	RegisterErrDuplicateUser     = "duplicate_user"
	RegisterErrWeakPassword      = "weak_password"
	RegisterErrAntiforgeryFailed = "antiforgery_failed"
	RegisterErrServerError       = "server_error"
)

type RegisterConfig struct {
	LoginPath    string
	RequireHTTPS bool
}

// RegisterHandler implements POST /api/auth/register for the SPA.
type RegisterHandler struct {
	Cfg    RegisterConfig
	Users  store.UserStore
	Clock  clock.Clock
	Logger *slog.Logger
}

type registerRequest struct {
	Username        string `json:"username"`
	Email           string `json:"email"`
	Password        string `json:"password"`
	PasswordConfirm string `json:"password_confirm"`
	ReturnURL       string `json:"return_url"`
}

func (h *RegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
		return
	}
	ctx := r.Context()
	if !APICSRFGuard(h.Cfg.RequireHTTPS).VerifyHeader(r) {
		h.respondWithError(w, http.StatusForbidden, RegisterErrAntiforgeryFailed)
		return
	}
	var body registerRequest
	if err := decodeJSON(r, &body); err != nil {
		h.respondWithError(w, http.StatusBadRequest, RegisterErrMissingFields)
		return
	}

	username := strings.TrimSpace(body.Username)
	email := strings.TrimSpace(body.Email)
	password := body.Password
	passwordConfirm := body.PasswordConfirm

	if username == "" || email == "" || password == "" || passwordConfirm == "" {
		h.respondWithError(w, http.StatusBadRequest, RegisterErrMissingFields)
		return
	}

	if password != passwordConfirm {
		h.respondWithError(w, http.StatusBadRequest, RegisterErrPasswordMismatch)
		return
	}

	if err := ValidatePassword(password); err != nil {
		h.respondWithError(w, http.StatusBadRequest, RegisterErrWeakPassword)
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
			h.respondWithError(w, http.StatusConflict, RegisterErrDuplicateUser)
			return
		}
		h.Logger.ErrorContext(r.Context(), "user store error during registration", "err", err)
		h.respondWithError(w, http.StatusInternalServerError, RegisterErrServerError)
		return
	}

	// Successfully registered. Send the SPA to the login page, keeping
	// any returnUrl so an in-progress authorize flow can resume. The
	// login handler validates the returnUrl again before using it.
	target := h.Cfg.LoginPath
	if body.ReturnURL != "" {
		target += "?returnUrl=" + url.QueryEscape(body.ReturnURL)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"redirect": target})
}

func (h *RegisterHandler) respondWithError(w http.ResponseWriter, status int, code string) {
	writeJSONError(w, status, code, registerErrorLabel(code))
}

func registerErrorLabel(code string) string {
	switch code {
	case RegisterErrMissingFields:
		return "Please fill out all fields."
	case RegisterErrPasswordMismatch:
		return "Passwords do not match."
	case RegisterErrWeakPassword:
		return "Password must be 8-72 characters and must not start or end with whitespace."
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
