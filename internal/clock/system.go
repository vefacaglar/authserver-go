package clock

import "time"

// SystemClock returns the real wall-clock time in UTC.
type SystemClock struct{}

var _ Clock = SystemClock{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }
