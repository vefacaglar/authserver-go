package grants

import "github.com/google/uuid"

func id1() uuid.UUID          { return uuid.New() }
func strPtr(s string) *string { return &s }
