package domain

import "time"

const DefaultSigningAlgorithm = "RS256"

type SigningKey struct {
	KeyID         string
	Algorithm     string
	PrivateKeyPEM string
	PublicKeyPEM  string
	CreatedAt     time.Time
	RetiredAt     *time.Time
	IsActive      bool
}
