package grants

import "github.com/google/uuid"

// newRandom is a tiny indirection so tests can swap a deterministic
// generator if they need to. Default uses crypto/rand via google/uuid.
var newRandom = func() [16]byte {
	return [16]byte(uuid.New())
}
