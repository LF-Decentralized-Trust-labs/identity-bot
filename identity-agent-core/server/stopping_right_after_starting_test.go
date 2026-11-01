package server

import (
	"testing"
)

// A server stopped at any moment after Start returns shuts down cleanly. The
// goroutine that serves used to read the server and listener fields when it
// ran, so a Stop that got in first (which clears them) left it serving nil.
func TestStoppingRightAfterStartingDoesNotPanic(t *testing.T) {
	for i := 0; i < 200; i++ {
		s, err := New(Config{DataDir: t.TempDir(), Port: 0, EntityType: "individual"})
		if err != nil {
			t.Skipf("server unavailable: %v", err)
		}
		if err := s.Start(); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		s.Stop()
	}
}
