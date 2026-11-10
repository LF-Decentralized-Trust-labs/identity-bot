package server

import (
	"fmt"
	"testing"
	"time"
)

// A table filled with callers whose every hit has aged out must not lock a new
// caller out: wouldAllow, which the relayed key-log gate asks before allow,
// clears them the same way allow does.
func TestAFullTableOfExpiredCallersAdmitsANewcomer(t *testing.T) {
	at := time.Now()
	r := newIPRateLimiterAt(5, time.Minute, func() time.Time { return at })
	for i := 0; i < maxRateLimitedClients; i++ {
		r.allow(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
	}
	at = at.Add(2 * time.Minute) // every hit has aged out
	if !r.wouldAllow("203.0.113.9") {
		t.Fatal("a newcomer was refused by a table full of expired callers")
	}
	if !r.allow("203.0.113.9") {
		t.Fatal("allow refused the newcomer wouldAllow admitted")
	}

	// A table full of live callers still refuses a newcomer.
	live := newIPRateLimiter(5, time.Minute)
	for i := 0; i < maxRateLimitedClients; i++ {
		live.allow(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
	}
	if live.wouldAllow("203.0.113.9") || live.allow("203.0.113.9") {
		t.Fatal("a newcomer was admitted to a table full of live callers")
	}
}
