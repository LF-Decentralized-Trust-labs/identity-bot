package server

import (
	"context"
	"sync"
	"time"

	"identity-agent-core/lockgate"
)

// THE WORK THAT NEEDS THE IDENTITY'S KEY (ADR-074 section 5).
//
// A core that is open runs work of its own: it keeps the relay up, anchors the
// record, tells witnesses, runs each add-on, and takes the scheduled backup.
// Several of those keep key material in memory for as long as they run. A lock
// that stopped accepting requests and left them running would leave an identity
// that is "locked" still signing, so this work is one scope: a lock ends it,
// waits for it, and drops what it cached; an unlock starts a new one.

// seedWorkWait bounds how long a lock waits for this work to return after
// telling it to stop.
var seedWorkWait = 5 * time.Second

// seedSession is one open period's work.
type seedSession struct {
	stop   chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// seedWorkState holds the current session, nil while none runs.
type seedWorkState struct {
	mu   sync.Mutex
	cur  *seedSession
	zero bool
}

// openToDoWork reports whether the identity is in a state that may run work
// that needs its key: not locked and not being locked.
func (s *CoreServer) openToDoWork() bool {
	if s.lock == nil {
		return true
	}
	if s.lock.isLocking() {
		return false
	}
	return s.lock.sess.State() != lockgate.StateLocked
}

// ensureSeedWork returns the current session, making one when the identity is
// open and none runs. It returns nil for a locked identity.
func (s *CoreServer) ensureSeedWork() *seedSession {
	if !s.openToDoWork() {
		return nil
	}
	st := &s.seedWork
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.cur == nil {
		ctx, cancel := context.WithCancel(s.backgroundContext())
		st.cur = &seedSession{stop: make(chan struct{}), ctx: ctx, cancel: cancel}
	}
	return st.cur
}

// runSeedWork starts fn in the current open period and counts it, so a lock can
// wait for it. It returns false, and starts nothing, when the identity is
// locked or the server has stopped. fn must return once stop closes or ctx ends.
func (s *CoreServer) runSeedWork(fn func(ctx context.Context, stop <-chan struct{})) bool {
	sess := s.ensureSeedWork()
	if sess == nil {
		return false
	}
	sess.wg.Add(1)
	if !s.inBackground(func(context.Context) {
		defer sess.wg.Done()
		fn(sess.ctx, sess.stop)
	}) {
		sess.wg.Done()
		return false
	}
	return true
}

// endSeedWork is what a lock (and a stop) does to the work above: tell it to
// end, drop what it cached, and wait for it to return. Safe to call when
// nothing runs.
func (s *CoreServer) endSeedWork() {
	st := &s.seedWork
	st.mu.Lock()
	sess := st.cur
	st.cur = nil
	st.mu.Unlock()
	if s.lock != nil {
		s.lock.mu.Lock()
		s.lock.workStarted = false
		s.lock.mu.Unlock()
	}
	if sess != nil {
		close(sess.stop)
		sess.cancel()
	}
	s.dropWhatTheWorkCached()
	if sess != nil {
		waitWithin(sess.wg.Wait, seedWorkWait, "work that needs the identity's key")
		// Anything that installed a cache in the moment before it saw the stop.
		s.dropWhatTheWorkCached()
	}
}

// dropWhatTheWorkCached forgets key material the work kept: the relay (its
// enrolment key and the session it signs with), the seeds held for other
// identities' key logs, and the scheduled backup's timers. Go may have copied
// what it drops and the operating system may have paged it, so this ends the
// reference and is not a guarantee of erasure; ending the process is (ADR-074
// section 5).
func (s *CoreServer) dropWhatTheWorkCached() {
	s.dropTheRelay()
	s.eventSigners.Range(func(k, _ any) bool { s.eventSigners.Delete(k); return true })
	if s.BackupService != nil && s.BackupService.Scheduler != nil {
		s.BackupService.Scheduler.Suspend()
	}
}

// dropTheRelay ends the relay generation that runs and installs none in its
// place. A relay still enrolling installs nothing, because its generation is no
// longer the current one.
func (s *CoreServer) dropTheRelay() {
	s.mu.Lock()
	if s.relayCancel != nil {
		s.relayCancel()
		s.relayCancel = nil
	}
	s.relayGen++
	s.relayFailure = nil
	old := s.RelayManager
	s.RelayManager = nil
	if s.EndpointService != nil {
		s.EndpointService.SetRelayManager(nil)
	}
	s.mu.Unlock()
	if old != nil {
		old.Stop()
	}
}
