package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/authprovider"
	"identity-agent-core/lockgate"
	"identity-agent-core/secureenclave"
	"identity-agent-core/secureenclave/seedwraptest"
)

func aGatedCore(t *testing.T, dir string) (*CoreServer, http.Handler) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.DataDir = dir
	cfg.LocalOwnerSecret = testOwnerSecret
	cfg.ProfileID = "profile-a"
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	return s, s.buildRouter()
}

var theNonce int

func askTheLock(t *testing.T, h http.Handler, method, path, body string, withSecret bool) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:52100"
	r.Header.Set("Content-Type", "application/json")
	if withSecret {
		r.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func aLogIn(score int) string {
	theNonce++
	b, _ := json.Marshal(map[string]any{
		"profile": "profile-a", "level": authprovider.LevelVerified, "score": score,
		"at": time.Now().UTC().Format(time.RFC3339), "nonce": strings.Repeat("z", 16) + string(rune('a'+theNonce%26)) + time.Now().Format("150405.000000"),
	})
	return string(b)
}

func stateOf(t *testing.T, h http.Handler) lockStateReply {
	t.Helper()
	w := askTheLock(t, h, http.MethodGet, "/api/lock/state", "", true)
	var st lockStateReply
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil || w.Code != 200 {
		t.Fatalf("lock state: %d %s", w.Code, w.Body.String())
	}
	return st
}

func TestALockedCoreAnswersOnlyTheLockRoutesAndReadsNoSeed(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	dir := t.TempDir()
	s, h := aGatedCore(t, dir)
	if st := stateOf(t, h); st.State != "open" || st.LockClass != "app_only" {
		t.Fatalf("a new identity is gated and open, app_only: %+v", st)
	}
	if !strings.Contains(stateOf(t, h).Statement, "app only") {
		t.Fatal("the statement must say what an app_only lock is")
	}
	if w := askTheLock(t, h, http.MethodPost, "/api/lock/lock", "", true); w.Code != 200 {
		t.Fatalf("log out: %d %s", w.Code, w.Body.String())
	}
	if st := stateOf(t, h); st.State != "locked" {
		t.Fatalf("%+v", st)
	}
	// EVERY other route is refused with 423, whatever it is and however it asks.
	checked := 0
	_ = chi.Walk(h.(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if strings.Contains(route, "*") || !strings.HasPrefix(route, "/api/") || isALockRoute(route) {
			return nil
		}
		path := strings.NewReplacer("{", "", "}", "").Replace(route)
		w := askTheLock(t, h, method, path, `{}`, true)
		checked++
		if w.Code != http.StatusLocked {
			t.Errorf("%s %s answered %d while locked: %s", method, route, w.Code, w.Body.String())
		}
		return nil
	})
	if checked < 50 {
		t.Fatalf("only %d routes were walked, so this proves little", checked)
	}
	_ = s
}

func TestTheUnlockRouteNeedsTheLocalOwnerProofAndAPassingResult(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	_, h := aGatedCore(t, t.TempDir())
	askTheLock(t, h, http.MethodPost, "/api/lock/lock", "", true)

	if w := askTheLock(t, h, http.MethodPost, "/api/lock/unlock", aLogIn(80), false); w.Code != http.StatusForbidden {
		t.Fatalf("an unlock with no owner proof: %d", w.Code)
	}
	if st := stateOf(t, h); st.State != "locked" {
		t.Fatal("a request without the proof opened the identity")
	}
	if w := askTheLock(t, h, http.MethodPost, "/api/lock/unlock", aLogIn(79), true); w.Code != http.StatusUnauthorized {
		t.Fatalf("a score of 79: %d %s", w.Code, w.Body.String())
	}
	if st := stateOf(t, h); st.State != "locked" {
		t.Fatal("a failing score opened the identity")
	}
	w := askTheLock(t, h, http.MethodPost, "/api/lock/unlock", aLogIn(80), true)
	if w.Code != 200 {
		t.Fatalf("the placeholder's 80 with the proof: %d %s", w.Code, w.Body.String())
	}
	var st lockStateReply
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if st.State != "open" || st.LockClass == "provider_bound" {
		t.Fatalf("%+v", st)
	}
	// An ordinary route is served again.
	if w := askTheLock(t, h, http.MethodGet, "/api/health", "", true); w.Code == http.StatusLocked {
		t.Fatal("an open identity refused an ordinary route")
	}
}

func TestACoreStartedOnALoggedOutProfileIsLockedAndOnALoggedInOneIsOpen(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	dir := t.TempDir()
	s1, h1 := aGatedCore(t, dir)
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 9
	}
	if err := secureenclave.StoreIdentityRootSeed(dir, seed); err != nil {
		t.Fatal(err)
	}
	s1.Stop() // the operating system killed the app: no log-out
	_, h2 := aGatedCore(t, dir)
	if st := stateOf(t, h2); st.State != "open" {
		t.Fatalf("a killed phone must reopen with nobody present: %+v", st)
	}
	if got, err := secureenclave.LoadRootSeed(dir); err != nil || got[0] != 9 {
		t.Fatalf("the seed after the restart: %v", err)
	}
	askTheLock(t, h2, http.MethodPost, "/api/lock/lock", "", true)
	_, h3 := aGatedCore(t, dir)
	if st := stateOf(t, h3); st.State != "locked" {
		t.Fatalf("after a log-out a restart stays locked: %+v", st)
	}
	_ = h1
	if _, err := secureenclave.LoadRootSeed(dir); err == nil {
		t.Fatal("the seed was readable on a locked identity")
	}
}

func TestAFailedDeletionIsNotALogOutAndTheIdentityKeepsServing(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	dir := t.TempDir()
	_, h := aGatedCore(t, dir)
	held := filepath.Join(dir, "gate", "device-held.key")
	_ = os.Remove(held)
	_ = os.MkdirAll(filepath.Join(held, "x"), 0o700) // cannot be removed
	w := askTheLock(t, h, http.MethodPost, "/api/lock/lock", "", true)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "not logged out") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if st := stateOf(t, h); st.State != "open" {
		t.Fatalf("a failed log-out must show the identity as open: %+v", st)
	}
	if w := askTheLock(t, h, http.MethodGet, "/api/health", "", true); w.Code == http.StatusLocked {
		t.Fatal("the identity stopped serving though it was not logged out")
	}
}

func TestARequestRunningWhenTheLockFiresIsCancelledAndNeverAnswersWithWhatItMade(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	s, _ := aGatedCore(t, t.TempDir())
	s.lock.drainWithin = 100 * time.Millisecond

	started := make(chan struct{})
	finish := make(chan struct{})
	slow := s.lock.guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-finish:
		}
		// The handler finishes its work anyway and tries to send a signature.
		w.Write([]byte(`{"signature":"PARTIAL"}`))
	}))
	var rec *httptest.ResponseRecorder
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rec = httptest.NewRecorder()
		slow.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/anything", nil).WithContext(context.Background()))
	}()
	<-started
	if err := s.lock.lockNow(); err != nil {
		t.Fatal(err)
	}
	close(finish)
	wg.Wait()
	if strings.Contains(rec.Body.String(), "PARTIAL") {
		t.Fatalf("a request the lock cancelled still answered with its result: %s", rec.Body.String())
	}
	if rec.Code != http.StatusLocked {
		t.Fatalf("the cancelled request was answered %d, want 423 identity is locked", rec.Code)
	}
}

func TestARequestThatFinishesWithinTheDrainIsAnsweredInFull(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	s, _ := aGatedCore(t, t.TempDir())
	started := make(chan struct{})
	h := s.lock.guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte("whole"))
	}))
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/x", nil)); close(done) }()
	<-started
	if err := s.lock.lockNow(); err != nil {
		t.Fatal(err)
	}
	<-done
	if rec.Body.String() != "whole" {
		t.Fatalf("a request within the drain was cut: %q", rec.Body.String())
	}
}

func TestAProfileMadeBeforeGatesSaysItIsNotLocked(t *testing.T) {
	// A machine with no working hardware key (production build): nothing can be
	// gated, and the core says so rather than claiming a lock.
	defer secureenclave.UseSeedWrapper(seedwraptest.Wrapper{Works: false})()
	_, h := aGatedCore(t, t.TempDir())
	if st := stateOf(t, h); st.State != "ungated" || st.LockClass != "none" || !strings.Contains(st.Statement, "Nothing locks") {
		t.Fatalf("%+v", st)
	}
}

func TestADesktopCoreStaysLockedWithoutARootDeviceVoucher(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	cfg := DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.LocalOwnerSecret = testOwnerSecret
	cfg.ProfileID = "profile-a"
	cfg.GateMode = lockgate.ModeController
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	h := s.buildRouter()
	askTheLock(t, h, http.MethodPost, "/api/lock/lock", "", true)
	w := askTheLock(t, h, http.MethodPost, "/api/lock/unlock", aLogIn(80), true)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a desktop scoring itself: %d %s", w.Code, w.Body.String())
	}
	if st := stateOf(t, h); st.State != "locked" {
		t.Fatalf("the desktop opened without its root device: %+v", st)
	}
}

func TestAnIdentityWithASeedBeforeGatesIsServedAsItWasAndSaysSo(t *testing.T) {
	dir := t.TempDir()
	// A seed stored while nothing is gated: made before gates existed.
	if err := secureenclave.StoreIdentityRootSeed(dir, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	_, h := aGatedCore(t, dir)
	if st := stateOf(t, h); st.State != "ungated" || st.LockClass != "none" {
		t.Fatalf("%+v", st)
	}
	if w := askTheLock(t, h, http.MethodPost, "/api/lock/lock", "", true); w.Code != http.StatusConflict {
		t.Fatalf("logging out an identity with no lock must say it has none: %d", w.Code)
	}
}
