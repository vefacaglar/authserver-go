// Package clock provides an abstraction over the current time so protocol code
// can be tested with a deterministic fake instead of relying on the wall clock.
package clock

import "time"

// Clock returns the current time. Implementations must return times in UTC so
// the domain layer never has to think about local time zones.
type Clock interface {
	Now() time.Time
}
