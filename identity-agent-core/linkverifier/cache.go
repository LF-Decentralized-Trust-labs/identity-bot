package linkverifier

import (
	"sync"
	"time"
)

type cacheEntry struct {
	result    VerificationResult
	expiresAt time.Time
}

type cache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	posTTL  time.Duration
	negTTL  time.Duration
}

func newCache() *cache {
	return &cache{
		entries: make(map[string]cacheEntry),
		posTTL:  5 * time.Minute,
		negTTL:  30 * time.Second,
	}
}

func (c *cache) get(key string) (VerificationResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || time.Now().After(e.expiresAt) {
		delete(c.entries, key)
		return VerificationResult{}, false
	}
	r := e.result
	r.Cached = true
	return r, true
}

func (c *cache) set(key string, r VerificationResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ttl := c.posTTL
	if r.Outcome == OutcomeUnverified {
		ttl = c.negTTL
	}
	c.entries[key] = cacheEntry{result: r, expiresAt: time.Now().Add(ttl)}
}

func (c *cache) purge(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}
