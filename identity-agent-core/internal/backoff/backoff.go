// Package backoff is the one doubling wait: a retry waits start, then twice
// that, and so on up to max. Reconnecting to a relay and telling an app over
// its rate when to try again both wait this way.
package backoff

import "time"

// Wait is how long to wait before attempt n (0 first): start doubling to max.
// It never exceeds max, and a start above max is max.
func Wait(start, max time.Duration, attempt int) time.Duration {
	d := start
	for i := 0; i < attempt && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	return d
}
