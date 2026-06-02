package domain

import "time"

// DataProtectionKey is one entry in the cookie data-protection key ring.
// Each key carries the symmetric material used to sign+encrypt the session
// cookie (HashKey + BlockKey for gorilla/securecookie) and the CSRF token
// key. Keys are generated server-side and persisted so every instance
// shares them and they survive restarts — the equivalent of ASP.NET Core
// Data Protection's persisted key ring.
//
// The ring supports rotation: the active key signs new cookies, while
// retired keys are kept so cookies issued under them still decode until
// they expire.
type DataProtectionKey struct {
	KeyID     string
	HashKey   []byte
	BlockKey  []byte
	CSRFKey   []byte
	CreatedAt time.Time
	RetiredAt *time.Time
	IsActive  bool
}
