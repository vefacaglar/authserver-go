package admin

import "crypto/rand"

// randRead is a small alias for crypto/rand.Read so the test file
// can use it without importing the package directly. (We split it
// out so the test file's imports stay short.)
func randRead(p []byte) (int, error) { return rand.Read(p) }
