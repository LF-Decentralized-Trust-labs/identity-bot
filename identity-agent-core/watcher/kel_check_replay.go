package watcher

import (
	"sync"
	"time"
)

// kelCheckWindow is how far a request's time may be from this agent's clock,
// and so how long a request is remembered.
const kelCheckWindow = 60 * time.Second

// maxRemembered bounds the replay cache. Only requests a contact signed are
// remembered, so it is reached only by a contact, which is also rate limited.
const maxRemembered = 4096

// replayCache remembers the signed requests answered inside the window, so one
// captured in transit cannot be sent again.
type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// first reports whether key has not been seen inside the window, and records it.
// It also refuses, without recording, when the cache is full of live entries.
func (c *replayCache) first(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]time.Time{}
	}
	for k, at := range c.seen {
		if now.Sub(at) > 2*kelCheckWindow {
			delete(c.seen, k)
		}
	}
	if _, dup := c.seen[key]; dup || len(c.seen) >= maxRemembered {
		return false
	}
	c.seen[key] = now
	return true
}
