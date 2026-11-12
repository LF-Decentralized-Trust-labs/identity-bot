package server

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"identity-agent-core/secureenclave/seedwraptest"
)

func openWorkOf(s *CoreServer) *seedSession {
	s.seedWork.mu.Lock()
	defer s.seedWork.mu.Unlock()
	return s.seedWork.cur
}

// A lock ends the work that needs the key and drops what it cached; an unlock
// starts it again (ADR-074 section 5).
func TestALockEndsTheWorkThatNeedsTheKeyAndAnUnlockStartsItAgain(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	s, h := aGatedCore(t, t.TempDir())
	s.startWhatNeedsTheIdentity()
	before := openWorkOf(s)
	if before == nil {
		t.Fatal("an open identity runs no work that needs its key")
	}

	// A worker that returns only when told to, and a cached seed and relay.
	stopped := make(chan struct{})
	if !s.runSeedWork(func(ctx context.Context, stop <-chan struct{}) {
		select {
		case <-stop:
		case <-ctx.Done():
		}
		close(stopped)
	}) {
		t.Fatal("work was refused on an open identity")
	}
	s.eventSigners.Store("EOther", make([]byte, 32))
	relayEnded := false
	s.mu.Lock()
	s.relayCancel = func() { relayEnded = true }
	gen := s.relayGen
	s.mu.Unlock()

	if w := askTheLock(t, h, http.MethodPost, "/api/lock/lock", "", true); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	select {
	case <-stopped:
	default:
		t.Fatal("work that needs the key was still running after the lock returned")
	}
	if openWorkOf(s) != nil {
		t.Fatal("a locked identity still has an open period's work")
	}
	if !relayEnded || s.relayGen == gen {
		t.Fatal("the relay was not ended by the lock")
	}
	if _, ok := s.eventSigners.Load("EOther"); ok {
		t.Fatal("a seed cached for another identity's key log survived the lock")
	}
	s.lock.mu.Lock()
	started := s.lock.workStarted
	s.lock.mu.Unlock()
	if started {
		t.Fatal("workStarted stayed true after the lock")
	}
	if s.runSeedWork(func(context.Context, <-chan struct{}) {}) {
		t.Fatal("work that needs the key was started on a locked identity")
	}

	if w := askTheLock(t, h, http.MethodPost, "/api/lock/unlock", aLogIn(80), true); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	after := openWorkOf(s)
	if after == nil || after == before {
		t.Fatal("an unlock did not start a new open period's work")
	}
	select {
	case <-after.stop:
		t.Fatal("the new work was started already stopped")
	default:
	}
}

// Nothing signs after a lock: a seed a worker cached is gone, and a seed read
// afresh is refused because a locked profile gives none.
func TestNothingSignsAfterALock(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	dir := t.TempDir()
	s, _ := aGatedCore(t, dir)
	s.startWhatNeedsTheIdentity()
	s.eventSigners.Store("EOther", make([]byte, 32))
	if _, err := s.signEventFor("EOther", "", []byte("an event")); err != nil {
		t.Fatalf("setup: the cached seed should sign while open: %v", err)
	}
	if err := s.lock.lockNow(); err != nil {
		t.Fatal(err)
	}
	if sig, err := s.signEventFor("EOther", "", []byte("an event")); err == nil {
		t.Fatalf("signed after the lock: %s", sig)
	}
	if seed, err := ensureRootSeed(dir); err == nil {
		t.Fatalf("a locked profile gave up a seed (%d bytes)", len(seed))
	}
}

// A lock that cannot drop the key leaves the identity open, and its work running.
func TestAFailedLockLeavesTheWorkRunning(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	dir := t.TempDir()
	s, h := aGatedCore(t, dir)
	s.startWhatNeedsTheIdentity()
	held := filepath.Join(dir, "gate", "device-held.key")
	_ = os.Remove(held)
	_ = os.MkdirAll(filepath.Join(held, "x"), 0o700) // cannot be removed
	if w := askTheLock(t, h, http.MethodPost, "/api/lock/lock", "", true); w.Code != http.StatusInternalServerError {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	cur := openWorkOf(s)
	if cur == nil {
		t.Fatal("the identity is still open but its work did not start again")
	}
	select {
	case <-cur.stop:
		t.Fatal("the restarted work is already stopped")
	default:
	}
}

// Witnessing asked for while locked waits, and its worker starts on unlock.
func TestWitnessingAskedForWhileLockedStartsOnUnlock(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	s, h := aGatedCore(t, t.TempDir())
	askTheLock(t, h, http.MethodPost, "/api/lock/lock", "", true)
	s.witnessing.witnessMu.Lock()
	s.witnessing.witnessJobs = map[string]witnessJob{"EOwner": {owner: "EOwner"}}
	s.witnessing.witnessMu.Unlock()
	s.kickWitnessing()
	s.witnessing.witnessMu.Lock()
	running := s.witnessing.witnessKick != nil
	s.witnessing.witnessMu.Unlock()
	if running {
		t.Fatal("a witnessing worker started on a locked identity")
	}
	if w := askTheLock(t, h, http.MethodPost, "/api/lock/unlock", aLogIn(80), true); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	s.witnessing.witnessMu.Lock()
	running = s.witnessing.witnessKick != nil
	s.witnessing.witnessMu.Unlock()
	if !running {
		t.Fatal("the witnessing worker did not start on unlock")
	}
}

// ---- hijacked connections (ADR-074 section 5) ----

func connsHeld(l *theLock) int { l.mu.Lock(); defer l.mu.Unlock(); return len(l.conns) }

func aServerThatHijacks(t *testing.T, l *theLock, h func(w http.ResponseWriter, r *http.Request)) string {
	t.Helper()
	srv := httptest.NewServer(l.guard(http.HandlerFunc(h)))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func TestAHijackedConnectionLeavesTheLocksSetWhenItCloses(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	s, _ := aGatedCore(t, t.TempDir())
	taken := make(chan net.Conn, 1)
	addr := aServerThatHijacks(t, s.lock, func(w http.ResponseWriter, r *http.Request) {
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		taken <- c
	})
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.Write([]byte("GET /ws HTTP/1.1\r\nHost: x\r\n\r\n"))
	c := <-taken
	if n := connsHeld(s.lock); n != 1 {
		t.Fatalf("a hijacked connection is not in the lock's set: %d", n)
	}
	c.Close()
	if n := connsHeld(s.lock); n != 0 {
		t.Fatalf("a closed connection stayed in the lock's set: %d", n)
	}
}

func TestARequestTheLockCancelledCannotHijackAConnectionAfterTheGrace(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	s, _ := aGatedCore(t, t.TempDir())
	s.lock.drainWithin = 50 * time.Millisecond
	inside := make(chan struct{})
	result := make(chan error, 1)
	addr := aServerThatHijacks(t, s.lock, func(w http.ResponseWriter, r *http.Request) {
		close(inside)
		<-r.Context().Done() // cancelled by the lock after the grace
		time.Sleep(50 * time.Millisecond)
		_, _, err := w.(http.Hijacker).Hijack()
		result <- err
	})
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.Write([]byte("GET /ws HTTP/1.1\r\nHost: x\r\n\r\n"))
	<-inside
	if err := s.lock.lockNow(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("a request the lock had cancelled took a connection over after the lock closed the rest")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never tried")
	}
	if n := connsHeld(s.lock); n != 0 {
		t.Fatalf("a connection is held after the lock: %d", n)
	}
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("the caller got no answer: %v", err)
	}
	if resp.StatusCode != http.StatusLocked {
		t.Fatalf("answered %d, want 423", resp.StatusCode)
	}
}
