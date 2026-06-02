// Package domain contains the plain data models used across the auth server.
//
// These structs are intentionally free of HTTP, persistence, and JOSE concerns.
// All times are stored in UTC. Code outside this package must obtain the
// current time through a clock.Clock implementation instead of calling
// time.Now directly so that tests can advance time deterministically.
package domain

import "time"

const (
	DefaultAccessTokenLifetimeSeconds          = 3600
	DefaultRefreshTokenLifetimeSeconds         = 2592000
	DefaultRefreshTokenAbsoluteLifetimeSeconds = 2592000
)

type TokenExpiration int

const (
	TokenExpirationSliding TokenExpiration = 0
	TokenExpirationAbsolute TokenExpiration = 1
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
