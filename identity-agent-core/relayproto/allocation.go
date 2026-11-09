package relayproto

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"
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

// AllocationLimiter counts requests per allocation in fixed one-minute windows.
type AllocationLimiter struct {
	PerMinute int
	Now       func() time.Time

	mu        sync.Mutex
	windows   map[string]*window
	lastSweep time.Time
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
		w = &window{start: now}
		l.windows[allocation] = w
		// Forget finished windows at most once a minute, so the cost of
		// sweeping is spread over a minute of requests, not paid by each.
		if now.Sub(l.lastSweep) >= time.Minute {
			l.lastSweep = now
			for k, old := range l.windows {
				if now.Sub(old.start) >= time.Minute {
					delete(l.windows, k)
				}
			}
		}
	}
	if w.count >= l.PerMinute {
		return false
	}
	w.count++
	return true
}

// CheckPrivateURL says whether publicURL is where a private allocation named
// label may be reached: a path at the relay's one host,
// https://<relay>/<label>, and never a host of its own (ADR-048 §8).
//
// The host name travels in clear in every TLS handshake (SNI), where the
// relay's network, the caller's ISP and anyone on the wire read it. A label
// in the host would show them a distinct name for each relationship every
// time it is used; in the path it is inside the encryption. An Identity Agent
// checks this before it holds a new private address, so a relay cannot hand
// it an address that gives the relationship away.
//
// It is for NEW allocations. An address an Identity Agent already holds in
// the retired subdomain form (https://<label>.<relay>) keeps working as it
// is; see ADR-048 §8, "Transition from per-relationship subdomains".
func CheckPrivateURL(publicURL, label string) error {
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return fmt.Errorf("a private address must be an https:// URL, not %q", publicURL)
	}
	if label == "" || strings.Contains(strings.ToLower(u.Hostname()), strings.ToLower(label)) {
		return fmt.Errorf("a private address must not carry its label in the host name, where the TLS handshake shows it")
	}
	if !strings.EqualFold(strings.TrimRight(u.EscapedPath(), "/"), "/"+label) || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("a private address must be a path at the relay: https://<relay>/<label>")
	}
	return nil
}
