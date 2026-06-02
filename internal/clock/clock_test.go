package clock

import (
	"testing"
	"time"
)

func TestFakeClock_Advance(t *testing.T) {
	start := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	fc := NewFakeClock(start)

	if got := fc.Now(); !got.Equal(start) {
		t.Fatalf("initial Now() = %v, want %v", got, start)
	}

	fc.Advance(5 * time.Minute)
	want := start.Add(5 * time.Minute)
	if got := fc.Now(); !got.Equal(want) {
		t.Errorf("after Advance(5m) Now() = %v, want %v", got, want)
	}

	fc.Advance(24 * time.Hour)
	want = start.Add(5*time.Minute + 24*time.Hour)
	if got := fc.Now(); !got.Equal(want) {
		t.Errorf("after further Advance(24h) Now() = %v, want %v", got, want)
	}
}

func TestFakeClock_Set(t *testing.T) {
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	fc := NewFakeClock(start)

	target := time.Date(2025, 6, 15, 9, 30, 0, 0, time.UTC)
	fc.Set(target)

	if got := fc.Now(); !got.Equal(target) {
		t.Errorf("after Set, Now() = %v, want %v", got, target)
	}
}

func TestFakeClock_NormalisesToUTC(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("timezone data not available: %v", err)
	}
	nonUTC := time.Date(2024, 1, 1, 12, 0, 0, 0, loc)

	fc := NewFakeClock(nonUTC)
	if got := fc.Now(); got.Location() != time.UTC {
		t.Errorf("NewFakeClock did not normalise: location = %v, want UTC", got.Location())
	}

	fc.Set(nonUTC.Add(2 * time.Hour))
	if got := fc.Now(); got.Location() != time.UTC {
		t.Errorf("Set did not normalise: location = %v, want UTC", got.Location())
	}
}

func TestSystemClock_NowIsUTC(t *testing.T) {
	got := SystemClock{}.Now()
	if got.Location() != time.UTC {
		t.Errorf("SystemClock.Now() location = %v, want UTC", got.Location())
	}
}
