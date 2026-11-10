package backoff

import (
	"testing"
	"time"
)

func TestWaitDoublesFromStartAndStopsAtMax(t *testing.T) {
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second}
	for n, w := range want {
		if got := Wait(time.Second, 5*time.Second, n); got != w {
			t.Errorf("attempt %d: want %v, got %v", n, w, got)
		}
	}
	if got := Wait(time.Minute, time.Second, 0); got != time.Second {
		t.Errorf("a start above max must be max, got %v", got)
	}
	if got := Wait(time.Second, time.Minute, 1<<30); got != time.Minute {
		t.Errorf("a huge attempt must be max, got %v", got)
	}
}
