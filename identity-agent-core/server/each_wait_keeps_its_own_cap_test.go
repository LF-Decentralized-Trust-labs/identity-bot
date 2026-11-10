package server

import (
	"net/http/httptest"
	"testing"
	"time"
)

// Each caller of the one backoff passes its own start and cap; a caller that
// passed the wrong one would still "double to a cap", so each is pinned here.
func TestEachRetryWaitDoublesFromItsStartToItsOwnCap(t *testing.T) {
	for _, c := range []struct {
		name string
		wait func(int) time.Duration
		// the wait at the first try, the second, and for ever after
		first, second, last time.Duration
	}{
		{"a failed registry event to the witnesses", telPushRetryGap, time.Minute, 2 * time.Minute, 6 * time.Hour},
		{"starting the relay manager", relayStartWait, 5 * time.Second, 10 * time.Second, 5 * time.Minute},
		{"a witness that has not yet moved on", movedOnWait, 30 * time.Second, time.Minute, time.Hour},
	} {
		first := 0
		if c.name != "starting the relay manager" {
			first = 1 // these count tries from one; the relay counts from zero
		}
		if got := c.wait(first); got != c.first {
			t.Errorf("%s: first wait %v, want %v", c.name, got, c.first)
		}
		if got := c.wait(first + 1); got != c.second {
			t.Errorf("%s: second wait %v, want %v", c.name, got, c.second)
		}
		for _, n := range []int{first + 40, first + 1000} {
			if got := c.wait(n); got != c.last {
				t.Errorf("%s: wait %d is %v, want the cap %v", c.name, n, got, c.last)
			}
		}
	}
}

// A refusal for the rate always names a whole second at least, so a client that
// reads Retry-After as an integer is never told to retry at once.
func TestARefusedRateNamesAtLeastASecond(t *testing.T) {
	for _, wait := range []time.Duration{0, time.Millisecond, 900 * time.Millisecond} {
		rec := httptest.NewRecorder()
		if !RefuseAnAppOverItsRate(rec, &AppOverItsRate{Wait: wait}) || rec.Code != 429 || rec.Header().Get("Retry-After") != "1" {
			t.Errorf("wait %v: %d Retry-After %q", wait, rec.Code, rec.Header().Get("Retry-After"))
		}
	}
	rec := httptest.NewRecorder()
	RefuseAnAppOverItsRate(rec, &AppOverItsRate{Wait: 1100 * time.Millisecond})
	if rec.Header().Get("Retry-After") != "2" {
		t.Errorf("1.1s rounded to %q", rec.Header().Get("Retry-After"))
	}
}
