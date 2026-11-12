package lockgate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/secureenclave"
)

func theJournalIsThere(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, gateDirName, changeJournalFile))
	return err == nil
}

// A crash leaves the new key under the device wrapper alone in the journal. A
// log-out finishes the change first, so a logged-out identity keeps no such key.
func TestALogOutFinishesAChangeACrashCutShort(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	seed := r.storeSeed()
	crash := errors.New("power cut")
	afterStep = func(s string) error {
		if s == "journalled" {
			return crash
		}
		return nil
	}
	t.Cleanup(func() { afterStep = nil })
	if err := r.s.ChangeSecret("", "correct horse"); !errors.Is(err, crash) {
		t.Fatal(err)
	}
	afterStep = nil
	if !theJournalIsThere(r.dir) {
		t.Fatal("the crash left no journal, so this tests nothing")
	}
	if err := r.s.Lock(); err != nil {
		t.Fatal(err)
	}
	if theJournalIsThere(r.dir) {
		t.Fatal("a logged-out identity still holds its new key in a journal")
	}
	if err := r.s.Unlock(r.result(80), "correct horse"); err != nil {
		t.Fatalf("the finished change does not open: %v", err)
	}
	if got, err := secureenclave.LoadRootSeed(r.dir); err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("seed after the log-out finished the change: %v", err)
	}
}

// And if it cannot be finished, the identity is reported as still open.
func TestALogOutThatCannotFinishAChangeReportsTheIdentityStillOpen(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	r.storeSeed()
	crash := errors.New("power cut")
	afterStep = func(s string) error {
		if s == "journalled" {
			return crash
		}
		return nil
	}
	t.Cleanup(func() { afterStep = nil })
	_ = r.s.ChangeSecret("", "correct horse")
	afterStep = nil
	if err := os.WriteFile(filepath.Join(r.dir, gateDirName, changeJournalFile), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.s.Lock(); !errors.Is(err, ErrNotLoggedOut) {
		t.Fatalf("log-out with an unfinishable change: %v", err)
	}
	if r.s.State() != StateOpen {
		t.Fatalf("state %s", r.s.State())
	}
}

// H1: an unreadable spent-nonces file fails closed, never as "nothing spent".
func TestAnUnreadableSpentNoncesFileRefusesTheLogIn(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	_ = r.s.Lock()
	if err := os.WriteFile(filepath.Join(r.dir, gateDirName, spentFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.s.Unlock(r.result(80), ""); !errors.Is(err, ErrReplayed) {
		t.Fatalf("an unreadable spent-nonces file let a log-in through: %v", err)
	}
	if r.s.State() != StateLocked {
		t.Fatal("not locked")
	}
}

// H2: the refusal comes from Require itself. The wrapper works, so the
// unwrapped-seed rule is not what refuses; the gate could not be founded
// because the gate copy cannot be written.
func TestRequireItselfRefusesASeedWhenFoundingFailedAnotherWay(t *testing.T) {
	r := newRig(t, ModePhone)
	// A non-empty directory where the gate copy goes: the write cannot land,
	// whoever runs the test.
	blocker := filepath.Join(r.dir, gateDirName, gateCopyFile)
	if err := os.MkdirAll(filepath.Join(blocker, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := r.s.Found(); err == nil {
		t.Fatal("founding succeeded with an unwritable gate copy")
	}
	// Not required: the store goes ahead (this is what Require changes).
	probe := t.TempDir()
	if err := secureenclave.StoreIdentityRootSeed(probe, make([]byte, 32)); err != nil {
		t.Fatalf("with the wrapper working a seed stores in an ungated profile: %v", err)
	}
	RequireFounding(r.dir, r.s)
	err := secureenclave.StoreIdentityRootSeed(r.dir, make([]byte, 32))
	if !errors.Is(err, secureenclave.ErrGateRequired) {
		t.Fatalf("the refusal did not come from the requirement: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(r.dir, "root_seed.json")); serr == nil {
		t.Fatal("a seed was written")
	}
	Require(probe)
	if err := secureenclave.StoreIdentityRootSeed(probe, make([]byte, 32)); !errors.Is(err, secureenclave.ErrGateRequired) {
		t.Fatalf("Require alone did not refuse: %v", err)
	}
}

// H3: Release finishes a change itself, for a core whose session never ran Reopen.
func TestUnlockFinishesAChangeEvenWhenNothingReopenedTheProfile(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	seed := r.storeSeed()
	crash := errors.New("power cut")
	afterStep = func(s string) error {
		if s == "seed" {
			return crash
		}
		return nil
	}
	t.Cleanup(func() { afterStep = nil })
	_ = r.s.ChangeSecret("", "correct horse")
	afterStep = nil
	// Logged out by deleting the device-held copy directly, with the journal left.
	if err := r.s.P.DeleteDeviceHeld(); err != nil {
		t.Fatal(err)
	}
	drop(r.dir)
	s2 := NewSession(OpenProfile(r.dir, "profile-a"), &Gate{Mode: ModePhone, Now: r.s.G.Now})
	if !theJournalIsThere(r.dir) {
		t.Fatal("no journal to finish")
	}
	if err := s2.Unlock(r.result(80), "correct horse"); err != nil {
		t.Fatalf("unlock with a pending change: %v", err)
	}
	if theJournalIsThere(r.dir) {
		t.Fatal("Release left the journal")
	}
	if got, err := secureenclave.LoadRootSeed(r.dir); err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("seed: %v", err)
	}
	r.s = s2
}

// H4: a phrase sealed under a gate, in a profile that has no gate now, is
// locked, not opened with no sealer.
func TestAGatedRecoveryPhraseInAProfileWithNoGateStaysLocked(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	phrase := []byte("abandon ability able about above absent")
	if err := secureenclave.StoreRecoveryPhrase(r.dir, phrase); err != nil {
		t.Fatal(err)
	}
	drop(r.dir)
	if err := os.RemoveAll(filepath.Join(r.dir, gateDirName)); err != nil {
		t.Fatal(err)
	}
	if OpenProfile(r.dir, "profile-a").Gated() {
		t.Fatal("the profile still counts as gated, so this does not reach the check")
	}
	got, err := secureenclave.LoadRecoveryPhrase(r.dir)
	if !errors.Is(err, secureenclave.ErrIdentityLocked) || got != nil {
		t.Fatalf("a gated phrase opened with no gate: %v", err)
	}
}
