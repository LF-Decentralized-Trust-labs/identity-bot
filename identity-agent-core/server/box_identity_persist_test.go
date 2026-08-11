package server

import (
	"os"
	"strings"
	"testing"

	"identity-agent-core/iacrypto"
)

// A machine that came back from a restart as a different identity would be
// unreachable to everyone who already knew it, and the owner's signature over
// the old one would point at something that no longer exists.
func TestTheIdentitySurvivesARestart(t *testing.T) {
	dir := t.TempDir()

	first := &CoreServer{DataDir: dir}
	made, err := first.ensureBoxIdentity("EOWNER")
	if err != nil {
		t.Fatal(err)
	}
	firstDID, err := made.Current.DID()
	if err != nil {
		t.Fatal(err)
	}

	// A different process, same disk — which is what a restart is.
	second := &CoreServer{DataDir: dir}
	back, err := second.ensureBoxIdentity("EOWNER")
	if err != nil {
		t.Fatal(err)
	}
	if back.AID != made.AID {
		t.Fatalf("the machine came back as %s, was %s", back.AID, made.AID)
	}
	backDID, err := back.Current.DID()
	if err != nil {
		t.Fatal(err)
	}
	if backDID.X25519 != firstDID.X25519 || backDID.MlKem != firstDID.MlKem {
		t.Fatal("the machine came back with different encryption keys, so anything sent to it " +
			"while it was down is unreadable and counterparties are encrypting to keys it no longer has")
	}

	// And what it commits to still matches what it holds.
	x, kem, err := iacrypto.AnchoredAgreementKeys(back.InceptionEvent)
	if err != nil {
		t.Fatal(err)
	}
	if err := backDID.MatchesAnchoredKeys(x, kem); err != nil {
		t.Fatalf("after a restart the keys no longer match what the identifier commits to: %v", err)
	}
}

// Asking again must never mint a second identity. The first is what the owner
// signed; a replacement is not a repair.
func TestAskingAgainDoesNotMintASecondIdentity(t *testing.T) {
	dir := t.TempDir()
	s := &CoreServer{DataDir: dir}
	first, err := s.ensureBoxIdentity("EOWNER")
	if err != nil {
		t.Fatal(err)
	}
	// Even under a different owner — which would otherwise produce a different
	// identifier entirely.
	again, err := s.ensureBoxIdentity("ESOMEONE-ELSE")
	if err != nil {
		t.Fatal(err)
	}
	if again.AID != first.AID {
		t.Fatal("a second identity was minted over the first")
	}
}

// A power cut during the write must not leave a machine that looks like it has
// no identity — because that leads to making a new one, which abandons the
// identifier counterparties hold.
func TestAHalfWrittenIdentityIsReportedRatherThanReplaced(t *testing.T) {
	dir := t.TempDir()
	s := &CoreServer{DataDir: dir}
	made, err := s.ensureBoxIdentity("EOWNER")
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(s.boxIdentityPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.boxIdentityPath(), raw[:len(raw)/2], 0600); err != nil {
		t.Fatal(err)
	}

	fresh := &CoreServer{DataDir: dir}
	loaded, err := fresh.loadBoxIdentity()
	if err == nil {
		t.Fatal("a truncated identity file was read as absent or valid, which would lead to " +
			"minting a replacement and abandoning the real one")
	}
	if loaded != nil {
		t.Error("a truncated file produced an identity")
	}
	if !strings.Contains(err.Error(), "abandon") {
		t.Errorf("the error does not say why this matters: %v", err)
	}
	_ = made
}

// A machine that has never been provisioned has no identity, and that is an
// ordinary state rather than a fault.
func TestNoIdentityYetIsNotAnError(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	got, err := s.loadBoxIdentity()
	if err != nil {
		t.Fatalf("a machine with no identity reported a fault: %v", err)
	}
	if got != nil {
		t.Error("a machine with no identity produced one")
	}
}

// Private keys on disk must not be readable by other users on the machine.
func TestTheIdentityFileIsNotWorldReadable(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	if _, err := s.ensureBoxIdentity("EOWNER"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(s.boxIdentityPath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Errorf("this machine's private keys are readable by other users: mode %v", info.Mode().Perm())
	}
}
