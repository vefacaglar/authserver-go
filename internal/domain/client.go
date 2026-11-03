// Package domain contains the plain data models used across the auth server.
//
// These structs are intentionally free of HTTP, persistence, and JOSE concerns.
// All times are stored in UTC. Code outside this package must obtain the
// current time through a clock.Clock implementation instead of calling
// time.Now directly so that tests can advance time deterministically.
package domain

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultAccessTokenLifetimeSeconds          = 3600
	DefaultRefreshTokenLifetimeSeconds         = 2592000
	DefaultRefreshTokenAbsoluteLifetimeSeconds = 2592000
)

type TokenExpiration int

const (
	TokenExpirationSliding  TokenExpiration = 0
	TokenExpirationAbsolute TokenExpiration = 1
)

// ClientProfile represents the high-level OAuth2/OIDC application archetype.
type ClientProfile string

const (
	// ClientProfileSPA is a public interactive client (browser SPA, mobile, native, CLI)
	// using Authorization Code + PKCE without a client secret or keypair.
	ClientProfileSPA ClientProfile = "spa"
	// ClientProfileWeb is a confidential interactive client (server-rendered web app / BFF)
	// using Authorization Code + PKCE authenticated with private_key_jwt.
	ClientProfileWeb ClientProfile = "web"
	// ClientProfileM2M is a confidential non-interactive service client (worker, daemon, microservice)
	// using the client_credentials grant authenticated with private_key_jwt.
	ClientProfileM2M ClientProfile = "m2m"
	// ClientProfileCustom covers hybrid confidential configurations (e.g. both interactive + M2M).
	ClientProfileCustom ClientProfile = "custom"
)

type Client struct {
	ClientID                            string
	DisplayName                         string
	RedirectURIs                        []string
	PostLogoutRedirectURIs              []string
	AllowedScopes                       []string
	RequirePKCE                         bool
	AllowRefreshTokens                  bool
	AllowClientCredentials              bool
	TokenEndpointAuthMethod             TokenEndpointAuthMethod
	JWKSJSON                            string
	AccessTokenLifetimeSeconds          int
	RefreshTokenLifetimeSeconds         int
	RefreshTokenAbsoluteLifetimeSeconds int
	RefreshTokenExpiration              TokenExpiration
	Properties                          map[string]string
}

// Profile derives the application archetype from the client's protocol capabilities.
func (c *Client) Profile() ClientProfile {
	if c.TokenEndpointAuthMethod == TokenEndpointAuthMethodPrivateKeyJWT {
		if c.AllowClientCredentials && len(c.RedirectURIs) == 0 && !c.AllowRefreshTokens {
			return ClientProfileM2M
		}
		if !c.AllowClientCredentials {
			return ClientProfileWeb
		}
		return ClientProfileCustom
	}
	return ClientProfileSPA
}

// ApplyProfile enforces the domain invariants of a high-level application archetype.
func (c *Client) ApplyProfile(profile ClientProfile) {
	switch profile {
	case ClientProfileSPA:
		c.TokenEndpointAuthMethod = TokenEndpointAuthMethodNone
		c.RequirePKCE = true
		c.AllowClientCredentials = false
		c.JWKSJSON = ""
	case ClientProfileWeb:
		c.TokenEndpointAuthMethod = TokenEndpointAuthMethodPrivateKeyJWT
		c.RequirePKCE = true
		c.AllowClientCredentials = false
	case ClientProfileM2M:
		c.TokenEndpointAuthMethod = TokenEndpointAuthMethodPrivateKeyJWT
		c.AllowClientCredentials = true
		c.AllowRefreshTokens = false
		c.RequirePKCE = false
		c.RedirectURIs = nil
		c.PostLogoutRedirectURIs = nil
		c.AllowedScopes = removeScope(c.AllowedScopes, "offline_access")
	}
}

// Normalize trims strings, deduplicates URI and scope lists, and enforces
// cross-field domain invariants (e.g. offline_access scope <-> AllowRefreshTokens).
func (c *Client) Normalize() {
	c.ClientID = strings.TrimSpace(c.ClientID)
	c.DisplayName = strings.TrimSpace(c.DisplayName)
	c.JWKSJSON = strings.TrimSpace(c.JWKSJSON)
	if c.TokenEndpointAuthMethod == "" {
		c.TokenEndpointAuthMethod = TokenEndpointAuthMethodNone
	}
	if c.TokenEndpointAuthMethod == TokenEndpointAuthMethodNone {
		c.AllowClientCredentials = false
		c.JWKSJSON = ""
	}
	c.RedirectURIs = cleanStringList(c.RedirectURIs)
	c.PostLogoutRedirectURIs = cleanStringList(c.PostLogoutRedirectURIs)
	c.AllowedScopes = cleanStringList(c.AllowedScopes)
	if !containsFold(c.AllowedScopes, "openid") {
		c.AllowedScopes = append([]string{"openid"}, c.AllowedScopes...)
	}
	if c.AllowRefreshTokens && !containsFold(c.AllowedScopes, "offline_access") {
		c.AllowedScopes = append(c.AllowedScopes, "offline_access")
	}
	if !c.AllowRefreshTokens {
		c.AllowedScopes = removeScope(c.AllowedScopes, "offline_access")
	}
}

// Validate checks domain invariants on a normalized Client.
func (c *Client) Validate() error {
	if c.ClientID == "" {
		return errors.New("client_id is required")
	}
	if !c.TokenEndpointAuthMethod.Valid() {
		return fmt.Errorf("unknown token_endpoint_auth_method %q", c.TokenEndpointAuthMethod)
	}
	for _, u := range c.RedirectURIs {
		if err := validateAbsoluteURI(u); err != nil {
			return fmt.Errorf("invalid redirect_uri %q: %w", u, err)
		}
	}
	for _, u := range c.PostLogoutRedirectURIs {
		if err := validateAbsoluteURI(u); err != nil {
			return fmt.Errorf("invalid post_logout_redirect_uri %q: %w", u, err)
		}
	}
	if c.AccessTokenLifetimeSeconds < 0 || c.RefreshTokenLifetimeSeconds < 0 || c.RefreshTokenAbsoluteLifetimeSeconds < 0 {
		return errors.New("token lifetimes cannot be negative")
	}
	if c.RefreshTokenExpiration != TokenExpirationSliding && c.RefreshTokenExpiration != TokenExpirationAbsolute {
		return errors.New("invalid refresh_token_expiration")
	}
	return nil
}

func validateAbsoluteURI(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("must be an absolute URI with scheme and host")
	}
	if parsed.Fragment != "" {
		return errors.New("URI must not contain a fragment (#)")
	}
	return nil
}

func cleanStringList(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	out := make([]string, 0, len(xs))
	seen := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		v := strings.TrimSpace(x)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func containsFold(xs []string, target string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, target) {
			return true
		}
	}
	return false
}

func removeScope(xs []string, target string) []string {
	if len(xs) == 0 {
		return nil
	}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if !strings.EqualFold(x, target) {
			out = append(out, x)
		}
	}
	return out
}

func (c *Client) AccessTokenLifetime() time.Duration {
	return time.Duration(c.effectiveAccessTokenLifetime()) * time.Second
}

func (c *Client) RefreshTokenLifetime() time.Duration {
	return time.Duration(c.effectiveRefreshTokenLifetime()) * time.Second
}

func (c *Client) RefreshTokenAbsoluteLifetime() time.Duration {
	return time.Duration(c.effectiveRefreshTokenAbsoluteLifetime()) * time.Second
}

func (c *Client) effectiveAccessTokenLifetime() int {
	if c.AccessTokenLifetimeSeconds <= 0 {
		return DefaultAccessTokenLifetimeSeconds
	}
	return c.AccessTokenLifetimeSeconds
}

func (c *Client) effectiveRefreshTokenLifetime() int {
	if c.RefreshTokenLifetimeSeconds <= 0 {
		return DefaultRefreshTokenLifetimeSeconds
	}
	return c.RefreshTokenLifetimeSeconds
}

func (c *Client) effectiveRefreshTokenAbsoluteLifetime() int {
	if c.RefreshTokenAbsoluteLifetimeSeconds <= 0 {
		return DefaultRefreshTokenAbsoluteLifetimeSeconds
	}
	return c.RefreshTokenAbsoluteLifetimeSeconds
}
