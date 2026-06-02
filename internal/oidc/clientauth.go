package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"go-authserver/internal/clock"
	"go-authserver/internal/domain"
	"go-authserver/internal/store"
	"go-authserver/internal/token"
)

// ClientAuthError is the typed error returned by AuthenticateClient.
// The TokenHandler turns it into a 401 + WWW-Authenticate + opaque
// invalid_client body. The Description and Cause are server-side
// only — the wire body is a fixed string so we don't leak
// information about which check failed.
type ClientAuthError struct {
	// Status is the HTTP status to return; always 401 for auth
	// failures (per the spec).
	Status int
	// Code is the OAuth error code to surface on the wire.
	// Always "invalid_client" so we don't leak the failure mode.
	Code string
	// Description is the server-side log reason. Never written to
	// the response body.
	Description string
	// Cause is the underlying verifier error, for log correlation.
	Cause error
}

func (e *ClientAuthError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("client auth: %s: %s: %v", e.Code, e.Description, e.Cause)
	}
	return fmt.Sprintf("client auth: %s: %s", e.Code, e.Description)
}

// ClientAuthConfig is the bundle of inputs AuthenticateClient reads.
// Keeping it as a struct makes call-site changes non-breaking.
type ClientAuthConfig struct {
	// IssuerURL is the issuer (matches the iss on the access/id
	// tokens the server issues). One of the audiences an
	// assertion's aud must contain.
	IssuerURL string
	// TokenEndpointURL is the absolute URL the assertion's aud
	// is allowed to carry.
	TokenEndpointURL string
	// AssertionCache records used jti values.
	AssertionCache token.ClientAssertionCache
	// AssertionSkew is the acceptable clock skew on assertion
	// exp/nbf checks.
	AssertionSkew time.Duration
	// Clock drives time-based checks.
	Clock clock.Clock
	// Logger receives structured entries for failed
	// authentications. Optional.
	Logger *slog.Logger
}

// AuthenticateClient resolves and verifies the client at the token
// endpoint. It supports two authentication methods:
//
//   - "none" (public client): the form's client_id is the only
//     credential. PKCE on the authorization_code path is the actual
//     proof-of-possession for public clients.
//   - "private_key_jwt" (confidential client): the form carries a
//     client_assertion JWT signed with the client's registered
//     private key. The assertion is verified against the client's
//     inline JWKS, with the strict checks described in
//     token.VerifyClientAssertion.
//
// On any failure AuthenticateClient returns a *ClientAuthError; the
// caller is expected to write a 401 with the same opaque body and
// log the Description server-side.
func AuthenticateClient(ctx context.Context, cfg ClientAuthConfig, clients store.ClientStore, form url.Values) (*domain.Client, error) {
	clientID := form.Get("client_id")
	if clientID == "" {
		return nil, &ClientAuthError{Status: http.StatusUnauthorized, Code: ErrInvalidClient, Description: "client_id is required"}
	}
	client, err := clients.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, &ClientAuthError{Status: http.StatusUnauthorized, Code: ErrInvalidClient, Description: "unknown client", Cause: err}
	}

	switch client.TokenEndpointAuthMethod {
	case domain.TokenEndpointAuthMethodNone:
		return client, nil
	case domain.TokenEndpointAuthMethodPrivateKeyJWT:
		return authenticateWithPrivateKeyJWT(ctx, cfg, client, form)
	default:
		return nil, &ClientAuthError{
			Status:      http.StatusUnauthorized,
			Code:        ErrInvalidClient,
			Description: fmt.Sprintf("unsupported client auth method %q", client.TokenEndpointAuthMethod),
		}
	}
}

func authenticateWithPrivateKeyJWT(ctx context.Context, cfg ClientAuthConfig, client *domain.Client, form url.Values) (*domain.Client, error) {
	assertionType := form.Get("client_assertion_type")
	if assertionType == "" {
		// Some clients send only client_assertion, omitting
		// client_assertion_type. Per the spec it is required,
		// but being lenient here gives a friendlier error.
		return nil, &ClientAuthError{Status: http.StatusUnauthorized, Code: ErrInvalidClient, Description: "client_assertion_type is required"}
	}
	if assertionType != token.ClientAssertionType {
		return nil, &ClientAuthError{Status: http.StatusUnauthorized, Code: ErrInvalidClient, Description: "unsupported client_assertion_type"}
	}
	assertion := form.Get("client_assertion")
	if assertion == "" {
		return nil, &ClientAuthError{Status: http.StatusUnauthorized, Code: ErrInvalidClient, Description: "client_assertion is required"}
	}

	audiences := []string{}
	if cfg.IssuerURL != "" {
		audiences = append(audiences, cfg.IssuerURL)
	}
	if cfg.TokenEndpointURL != "" {
		audiences = append(audiences, cfg.TokenEndpointURL)
	}
	if len(audiences) == 0 {
		return nil, &ClientAuthError{Status: http.StatusInternalServerError, Code: ErrServerError, Description: "client auth misconfigured: no audience"}
	}

	_, err := token.VerifyClientAssertion(ctx, token.ClientAssertionParams{
		Assertion:       assertion,
		JWKSJSON:        client.JWKSJSON,
		ExpectedIssuer:  client.ClientID,
		ExpectedSubject: client.ClientID,
		Audience:        audiences,
		Skew:            cfg.AssertionSkew,
		Cache:           cfg.AssertionCache,
		Clock:           cfg.Clock,
	})
	if err != nil {
		if cfg.Logger != nil {
			cfg.Logger.Warn("client assertion rejected", "client_id", client.ClientID, "err", err)
		}
		return nil, &ClientAuthError{
			Status:      http.StatusUnauthorized,
			Code:        ErrInvalidClient,
			Description: "client assertion failed verification",
			Cause:       err,
		}
	}
	return client, nil
}

// writeClientAuthError renders a *ClientAuthError to the wire with
// the 401 + WWW-Authenticate + opaque body the spec requires.
func writeClientAuthError(w http.ResponseWriter, err *ClientAuthError) {
	if err == nil {
		err = &ClientAuthError{Status: http.StatusUnauthorized, Code: ErrInvalidClient, Description: "unknown"}
	}
	if err.Status == 0 {
		err.Status = http.StatusUnauthorized
	}
	if err.Code == "" {
		err.Code = ErrInvalidClient
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="auth-server"`)
	writeJSONError(w, err.Status, err.Code, "client authentication failed")
}

// asClientAuthError is a small adapter for the cases where the
// error is a plain error rather than a *ClientAuthError (e.g. when
// callers wrap one). It never panics.
func asClientAuthError(err error) *ClientAuthError {
	if err == nil {
		return nil
	}
	var cae *ClientAuthError
	if errors.As(err, &cae) {
		return cae
	}
	return &ClientAuthError{Status: http.StatusUnauthorized, Code: ErrInvalidClient, Description: "client authentication failed", Cause: err}
}
