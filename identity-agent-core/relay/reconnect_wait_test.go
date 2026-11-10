package relay

import (
	"testing"
	"time"
)

// The reconnection wait starts at a second, doubles, and stops at 64 seconds.
func TestReconnectWaitDoublesFromASecondToSixtyFour(t *testing.T) {
	want := []time.Duration{1, 2, 4, 8, 16, 32, 64, 64}
	for i, w := range want {
		if got := reconnectWait(i); got != w*time.Second {
			t.Errorf("attempt %d: %v, want %v", i, got, w*time.Second)
		}
	}
	if got := reconnectWait(500); got != 64*time.Second {
		t.Errorf("a long outage waits %v", got)
	}
}
