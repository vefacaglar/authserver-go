package memory

import "errors"

var (
	errNil       = errors.New("memory: nil entity")
	errEmptyID   = errors.New("memory: empty id")
	errEmptyHash = errors.New("memory: empty hash")
)
