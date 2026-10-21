package relayproto

import (
	"crypto/rand"
	"encoding/base32"
	"regexp"
	"strings"
	"sync"
	"time"
)

// NewAllocationToken returns a private allocation's address label: 128 random
// bits, lowercase base32 so it is a valid DNS label. It is never derived from an
// identifier, so two allocations of one identity cannot be linked by their
// labels.
func NewAllocationToken() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic("relayproto: no randomness: " + err.Error())
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf))
}

var aidSegment = regexp.MustCompile(`^[A-Za-z0-9_-]{44,}$`)

// PrivateMayReach reports whether a private allocation passes a request. A
// private address serves the identity's artifacts to the counterparty it was
// made for, and accepts that counterparty's messages, and nothing else:
//
//   - GET or HEAD of /{aid}/did.json, /{aid}/kel, /{aid}/keri.cesr,
//     /{aid}/oobi, /oobi/{aid} and /.well-known/did-configuration.json;
//   - POST /didcomm, the identity's message endpoint.
//
// The Identity Agent applies its own, stricter rule per allocation; a relay
// applies this one so that a mistake on one side is not a hole.
func PrivateMayReach(method, path string) bool {
	path = strings.TrimSuffix(path, "/")
	switch method {
	case "POST":
		return path == "/didcomm"
	case "GET", "HEAD":
	default:
		return false
	}
	if path == "/.well-known/did-configuration.json" {
		return true
	}
	seg := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(seg) != 2 {
		return false
	}
	if seg[0] == "oobi" {
		return aidSegment.MatchString(seg[1])
	}
	if !aidSegment.MatchString(seg[0]) {
		return false
	}
	switch seg[1] {
	case "did.json", "kel", "keri.cesr", "oobi":
		return true
	}
	return false
}

// AllocationLimiter counts requests per allocation in fixed one-minute windows.
type AllocationLimiter struct {
	PerMinute int
	Now       func() time.Time

	mu      sync.Mutex
	windows map[string]*window
}

type window struct {
	start time.Time
	count int
}

// NewAllocationLimiter allows perMinute requests per allocation per minute.
// Use PublicRequestsPerMinute or PrivateRequestsPerMinute.
func NewAllocationLimiter(perMinute int) *AllocationLimiter {
	return &AllocationLimiter{PerMinute: perMinute, windows: map[string]*window{}}
}

// Allow reports whether one more request to the allocation is within its limit.
func (l *AllocationLimiter) Allow(allocation string) bool {
	now := time.Now()
	if l.Now != nil {
		now = l.Now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.windows[allocation]
	if w == nil || now.Sub(w.start) >= time.Minute {
		if len(l.windows) > 100000 {
			for k, old := range l.windows {
				if now.Sub(old.start) >= time.Minute {
					delete(l.windows, k)
				}
			}
		}
		w = &window{start: now}
		l.windows[allocation] = w
	}
	if w.count >= l.PerMinute {
		return false
	}
	w.count++
	return true
}
