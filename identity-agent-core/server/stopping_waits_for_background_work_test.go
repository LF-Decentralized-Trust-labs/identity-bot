package server

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Stopping the server waits for the work it started in the background, so
// nothing is still writing into the data directory once Stop returns.
func TestStoppingWaitsForWorkStillWritingToTheDataDirectory(t *testing.T) {
	s := agentWithNoIdentity(t)
	s.running = true
	written := filepath.Join(s.DataDir, "written-in-the-background")
	started := make(chan struct{})
	s.inBackground(func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		// Work that notices it is being stopped still finishes what it was
		// writing, as a witness receipt or an introduction does.
		time.Sleep(200 * time.Millisecond)
		if err := os.WriteFile(written, []byte("done"), 0o600); err != nil {
			t.Errorf("writing: %v", err)
		}
	})
	<-started
	s.Stop()
	if _, err := os.Stat(written); err != nil {
		t.Fatalf("Stop returned while background work was still writing: %v", err)
	}
}

// Once the server has stopped, no more background work is started, so none
// can begin writing after the caller has moved on.
func TestNothingIsStartedInTheBackgroundOnceStopped(t *testing.T) {
	s := agentWithNoIdentity(t)
	s.running = true
	s.Stop()
	var ran atomic.Bool
	s.inBackground(func(context.Context) { ran.Store(true) })
	time.Sleep(50 * time.Millisecond)
	if ran.Load() {
		t.Fatal("background work started after the server stopped")
	}
}

// Background work is cancelled when the server stops, rather than left to
// run out its own timeout.
func TestBackgroundWorkIsCancelledWhenTheServerStops(t *testing.T) {
	s := agentWithNoIdentity(t)
	s.running = true
	started := make(chan struct{})
	cancelled := make(chan struct{})
	s.inBackground(func(ctx context.Context) {
		close(started)
		select {
		case <-ctx.Done():
			close(cancelled)
		case <-time.After(30 * time.Second):
		}
	})
	<-started
	begun := time.Now()
	s.Stop()
	select {
	case <-cancelled:
	default:
		t.Fatal("the background work was not cancelled by Stop")
	}
	if waited := time.Since(begun); waited > 5*time.Second {
		t.Fatalf("Stop waited %s for work that should have been cancelled", waited)
	}
}
