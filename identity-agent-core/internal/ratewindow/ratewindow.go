// Package ratewindow is the one sliding-window rate limit: at most Limit hits
// per key in any Span. A caller at an unauthenticated route, and a person
// writing into a conversation, are both held to a count over a window.
package ratewindow

import (
	"sync"
	"time"
)

// Window counts hits per key over a sliding span.
type Window struct {
	limit   int
	span    time.Duration
	maxKeys int
	now     func() time.Time

	mu   sync.Mutex
	hits map[string][]time.Time
}

// New makes a window of limit hits per span. maxKeys bounds how many keys are
// remembered (0 is unbounded, for keys the caller has already vouched for);
// once it is reached and every key is live, a new key is refused rather than
// the table grown. now may be nil.
func New(limit int, span time.Duration, maxKeys int, now func() time.Time) *Window {
	if now == nil {
		now = time.Now
	}
	return &Window{limit: limit, span: span, maxKeys: maxKeys, now: now, hits: map[string][]time.Time{}}
}

// Allow counts a hit for key and reports whether it is within the limit. A hit
// over the limit, or for a key there is no room for, is not counted.
func (w *Window) Allow(key string) bool { return w.AllowAt(key, w.now()) }

// AllowAt is Allow judged at the moment now, for a caller that already holds
// the time it is deciding by.
func (w *Window) AllowAt(key string, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	cutoff := now.Add(-w.span)
	if !w.roomFor(key, cutoff) {
		return false
	}
	live := w.prune(key, cutoff)
	if len(live) >= w.limit {
		return false
	}
	w.hits[key] = append(live, now)
	return true
}

// Would says whether Allow(key) would let a hit through, counting nothing and
// remembering nothing.
func (w *Window) Would(key string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	cutoff := w.now().Add(-w.span)
	if !w.roomFor(key, cutoff) {
		return false
	}
	return w.count(key, cutoff) < w.limit
}

// Count is how many hits key has within the span.
func (w *Window) Count(key string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.prune(key, w.now().Add(-w.span)))
}

// Record counts a hit for key whether or not it is over the limit (the caller
// has already decided with Count). It reports false only when there is no room
// for a new key.
func (w *Window) Record(key string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	cutoff := now.Add(-w.span)
	if !w.roomFor(key, cutoff) {
		return false
	}
	w.hits[key] = append(w.prune(key, cutoff), now)
	return true
}

// Keys is how many keys are remembered.
func (w *Window) Keys() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.hits)
}

// Remembers says whether key is in the table.
func (w *Window) Remembers(key string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.hits[key]
	return ok
}

// prune forgets key's hits older than cutoff and returns the rest. w.mu held.
func (w *Window) prune(key string, cutoff time.Time) []time.Time {
	prev, ok := w.hits[key]
	if !ok {
		return nil
	}
	live := prev[:0]
	for _, t := range prev {
		if t.After(cutoff) {
			live = append(live, t)
		}
	}
	w.hits[key] = live
	return live
}

func (w *Window) count(key string, cutoff time.Time) int {
	n := 0
	for _, t := range w.hits[key] {
		if t.After(cutoff) {
			n++
		}
	}
	return n
}

// roomFor reports whether key can be counted: it is already known, or the
// table has room after forgetting keys whose every hit has aged out. If that
// frees nothing the table is full of live keys: refuse the newcomer rather than
// grow. Allow, Would and Record all ask it, so a table of expired keys never
// locks a newcomer out. w.mu held.
func (w *Window) roomFor(key string, cutoff time.Time) bool {
	if w.maxKeys <= 0 {
		return true
	}
	if _, known := w.hits[key]; known || len(w.hits) < w.maxKeys {
		return true
	}
	for k, ts := range w.hits {
		if len(ts) == 0 || !ts[len(ts)-1].After(cutoff) {
			delete(w.hits, k)
		}
	}
	return len(w.hits) < w.maxKeys
}
