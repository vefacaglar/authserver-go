package domain

type TokenEndpointAuthMethod string

const (
	TokenEndpointAuthMethodNone          TokenEndpointAuthMethod = "none"
	TokenEndpointAuthMethodPrivateKeyJWT TokenEndpointAuthMethod = "private_key_jwt"
)

func (m TokenEndpointAuthMethod) Valid() bool {
	switch m {
	case TokenEndpointAuthMethodNone, TokenEndpointAuthMethodPrivateKeyJWT:
		return true
	default:
		return false
	}
}
