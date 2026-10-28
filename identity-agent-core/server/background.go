package server

import (
	"context"
	"log"
	"sync"
	"time"
)

// backgroundWork is the work the server starts and does not wait for inline:
// telling witnesses about a new identity, introducing ourselves to a contact,
// the loops that anchor the record and sweep what is lent.
//
// Most of it writes to the data directory when it finishes. Started with a
// bare `go`, nothing could wait for it, so stopping the server closed the
// store and returned while that work was still writing, and a caller removing
// the directory found it being written to. Everything started through
// inBackground is cancelled and waited for when the server stops.
type backgroundWork struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	ended  bool
	wg     sync.WaitGroup
}

// backgroundStopWait bounds how long stopping waits for background work that
// does not notice its context promptly. Past it, the server stops anyway and
// says what it did not wait for.
var backgroundStopWait = 15 * time.Second

// backgroundContext is the context background work runs under: the server's
// own, so it ends when the server stops.
func (s *CoreServer) backgroundContext() context.Context {
	b := &s.background
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.contextLocked(s.AppCtx)
}

func (b *backgroundWork) contextLocked(parent context.Context) context.Context {
	if b.ctx == nil {
		if parent == nil {
			parent = context.Background()
		}
		b.ctx, b.cancel = context.WithCancel(parent)
		if b.ended {
			b.cancel()
		}
	}
	return b.ctx
}

// inBackground runs fn in its own goroutine, under the server's background
// context, and counts it so that stopping the server waits for it. Once the
// server has stopped, nothing more is started.
func (s *CoreServer) inBackground(fn func(ctx context.Context)) {
	b := &s.background
	b.mu.Lock()
	if b.ended {
		b.mu.Unlock()
		return
	}
	ctx := b.contextLocked(s.AppCtx)
	b.wg.Add(1)
	b.mu.Unlock()
	go func() {
		defer b.wg.Done()
		fn(ctx)
	}()
}

// endBackground cancels the background work, refuses any more, and waits up
// to within for what is running to finish. It reports whether everything did.
func (s *CoreServer) endBackground(within time.Duration) bool {
	s.closeBackground()
	return s.waitForBackground(within)
}

// closeBackground cancels the background work and refuses any more.
func (s *CoreServer) closeBackground() {
	b := &s.background
	b.mu.Lock()
	b.ended = true
	if b.cancel != nil {
		b.cancel()
	}
	b.mu.Unlock()
}

// waitForBackground waits up to within for the background work to finish,
// once closeBackground has refused any more. It reports whether it did.
func (s *CoreServer) waitForBackground(within time.Duration) bool {
	return waitWithin(s.background.wg.Wait, within, "background work")
}

// waitWithin calls wait and returns true once it returns, or false after
// within, saying what it stopped waiting for.
func waitWithin(wait func(), within time.Duration, what string) bool {
	done := make(chan struct{})
	go func() {
		wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(within):
		log.Printf("[identity-agent-core] stopped without waiting any longer for %s, "+
			"still running after %s", what, within)
		return false
	}
}
