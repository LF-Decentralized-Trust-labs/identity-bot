package login

import (
	"math"
	"testing"
	"time"
)

// A caller can narrow the window an assertion's dt must fall in, or widen it
// up to an hour, and no further. A window of any size let an assertion
// captured years ago be presented again; one large enough to overflow its
// Duration wrapped around to something nobody chose.
func TestAFreshnessWindowIsNeverWiderThanAnHour(t *testing.T) {
	aid, seed, keyLog := aRealIdentity(t)
	const nonce, aud = "n", "Example RP"

	at := func(age time.Duration) Assertion {
		a := anAssertion(t, aid, keyLog, seed, nonce, aud)
		a.Dt = time.Now().Add(-age).UTC().Format(time.RFC3339)
		if err := SignAssertion(&a, seed); err != nil {
			t.Fatal(err)
		}
		return a
	}

	for _, c := range []struct {
		name   string
		age    time.Duration
		window int
		valid  bool
	}{
		{"a fresh assertion, the default window", 0, 0, true},
		{"six minutes old, the default window", 6 * time.Minute, 0, false},
		{"six minutes old, a negative window is the default", 6 * time.Minute, -1, false},
		{"fifty minutes old, a window of an hour", 50 * time.Minute, 3600, true},
		{"two hours old, a window of a million seconds", 2 * time.Hour, 1_000_000, false},
		{"from 2001, the largest window there is", 25 * 365 * 24 * time.Hour, math.MaxInt, false},
		{"from 2001, a window that overflows a Duration", 25 * 365 * 24 * time.Hour, math.MaxInt64 / 1_000_000_000 * 4, false},
	} {
		res := VerifyAssertion(at(c.age), nonce, aud, testSite, c.window)
		if res.Valid != c.valid {
			t.Errorf("%s: valid=%v (%s), want %v", c.name, res.Valid, res.Reason, c.valid)
		}
		if !c.valid && res.Reason != "dt outside freshness window" {
			t.Errorf("%s: refused as %q, want the freshness window", c.name, res.Reason)
		}
	}
}
