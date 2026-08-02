package server

import (
	"testing"
)

// Collecting owners before changing anything.
//
// The ceremony exists so that bringing others in is a separate, unhurried step
// from founding: one party creates an identity, it works immediately, and others
// join later. Nothing changes until everybody invited has accepted, because a
// half-applied ownership change is worse than none — some people believing they
// control something they do not.

func ceremonyServer(t *testing.T) *CoreServer {
	t.Helper()
	return &CoreServer{DataDir: t.TempDir()}
}

func collecting(names ...string) *OwnerCeremony {
	c := &OwnerCeremony{
		ID: "ceremony-1", Threshold: len(names) + 1, Status: ceremonyCollecting,
		OwnPublicKey: "DOWN-PRE-ROTATED", OwnNextPublicKey: "DOWN-NEXT",
	}
	for i, n := range names {
		c.Invited = append(c.Invited, CeremonyInvitee{
			Name: n, Token: "tok-" + string(rune('a'+i)),
		})
	}
	return c
}

func TestNothingHappensUntilEverybodyHasAccepted(t *testing.T) {
	s := ceremonyServer(t)
	ceremonyMu.Lock()
	if err := s.saveCeremony(collecting("Ada", "Grace")); err != nil {
		t.Fatal(err)
	}
	ceremonyMu.Unlock()

	c, complete, err := s.recordAcceptance("tok-a", "EADA", "DADA", "DADA-NEXT")
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("the acceptance was not recorded against the ceremony")
	}
	if complete {
		t.Fatal("the ceremony completed with one of two owners still outstanding")
	}
	if got := c.Outstanding(); len(got) != 1 || got[0] != "Grace" {
		t.Errorf("outstanding is %v — it should name who is still missing", got)
	}

	_, complete, err = s.recordAcceptance("tok-b", "EGRACE", "DGRACE", "DGRACE-NEXT")
	if err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Fatal("the last acceptance did not complete the ceremony")
	}
}

// A second scan of the same code is somebody checking it worked. It must not
// overwrite the key they already committed to — that key is going into a
// rotation, and replacing it silently would produce an event naming a key they
// never agreed to.
func TestScanningTwiceDoesNotReplaceTheKeyAlreadyGiven(t *testing.T) {
	s := ceremonyServer(t)
	ceremonyMu.Lock()
	s.saveCeremony(collecting("Ada"))
	ceremonyMu.Unlock()

	s.recordAcceptance("tok-a", "EADA", "DADA", "DADA-NEXT")
	s.recordAcceptance("tok-a", "EIMPOSTER", "DIMPOSTER", "DIMPOSTER-NEXT")

	ceremonyMu.Lock()
	c, _ := s.loadCeremony()
	ceremonyMu.Unlock()
	if c.Invited[0].PublicKey != "DADA" {
		t.Errorf("a second scan replaced the key: %q", c.Invited[0].PublicKey)
	}
}

// An invite that belongs to no ceremony is the ordinary founding-signer case.
// It must fall through rather than error, or founding breaks.
func TestATokenFromNoCeremonyFallsThrough(t *testing.T) {
	s := ceremonyServer(t)

	c, complete, err := s.recordAcceptance("some-other-token", "EX", "DX", "DX-NEXT")
	if err != nil {
		t.Fatalf("a founding-signer redemption errored: %v", err)
	}
	if c != nil || complete {
		t.Error("a token from no ceremony was treated as part of one")
	}
}

// Somebody who accepted has committed both halves: the key they will sign with
// and the one they will rotate into. Without the second, the resulting key set
// commits to no successors and the identity could never change ownership again
// — its last change made without anybody realising.
func TestAnOwnerWhoCommitsNoSuccessorHasNotAccepted(t *testing.T) {
	partial := CeremonyInvitee{Name: "Ada", PairwiseAID: "EADA", PublicKey: "DADA"}
	if partial.Accepted() {
		t.Error("an owner with no successor key counted as having accepted")
	}
	full := partial
	full.NextPublicKey = "DADA-NEXT"
	if !full.Accepted() {
		t.Error("a complete acceptance was not recognised")
	}
}

// A ceremony that failed and does not say why leaves everyone unsure whether
// control actually changed, which is the worst of the three states it could be
// in.
func TestAFailedCeremonyRecordsWhy(t *testing.T) {
	s := ceremonyServer(t)
	ceremonyMu.Lock()
	s.saveCeremony(collecting("Ada"))
	ceremonyMu.Unlock()

	if err := s.finishCeremony(ceremonyFailed, "the rotation was refused", ""); err != nil {
		t.Fatal(err)
	}
	ceremonyMu.Lock()
	c, _ := s.loadCeremony()
	ceremonyMu.Unlock()

	if c.Status != ceremonyFailed {
		t.Errorf("status is %q", c.Status)
	}
	if c.Detail == "" {
		t.Error("a failed ceremony recorded no reason")
	}
}

// Applying records the event that made it real, so the ceremony and the key log
// can be reconciled by anyone reading both.
func TestApplyingRecordsTheRotationThatDidIt(t *testing.T) {
	s := ceremonyServer(t)
	ceremonyMu.Lock()
	s.saveCeremony(collecting("Ada"))
	ceremonyMu.Unlock()

	s.finishCeremony(ceremonyApplied, "", "EROTATION-SAID")

	ceremonyMu.Lock()
	c, _ := s.loadCeremony()
	ceremonyMu.Unlock()
	if c.RotationSAID != "EROTATION-SAID" {
		t.Errorf("rotation said is %q", c.RotationSAID)
	}
	if c.AppliedAt.IsZero() {
		t.Error("nothing recorded when it was applied")
	}
}

// Once applied, a late scan of an old code must not be recorded — the rotation
// has already happened and the key set is fixed.
func TestALateAcceptanceIntoAnAppliedCeremonyIsIgnored(t *testing.T) {
	s := ceremonyServer(t)
	ceremonyMu.Lock()
	s.saveCeremony(collecting("Ada"))
	ceremonyMu.Unlock()
	s.finishCeremony(ceremonyApplied, "", "EROT")

	c, complete, err := s.recordAcceptance("tok-a", "EADA", "DADA", "DADA-NEXT")
	if err != nil {
		t.Fatal(err)
	}
	if c != nil || complete {
		t.Error("an acceptance was recorded into a ceremony that had already been applied")
	}
}

// The digests committed as next keys must be over the SUCCESSOR keys. Digesting
// the current set instead would pre-commit to keys already in use, which defeats
// pre-rotation entirely.
func TestNextKeyDigestsAreOverTheSuccessorKeys(t *testing.T) {
	current := []string{"DCURRENT-A", "DCURRENT-B"}
	successors := []string{"DNEXT-A", "DNEXT-B"}

	fromCurrent, err := digestsOf(current)
	if err != nil {
		t.Fatal(err)
	}
	fromSuccessors, err := digestsOf(successors)
	if err != nil {
		t.Fatal(err)
	}
	for i := range fromCurrent {
		if fromCurrent[i] == fromSuccessors[i] {
			t.Fatal("the digests do not distinguish current keys from successors")
		}
	}
}

func TestAnOwnerWithNoSuccessorCannotBeCommitted(t *testing.T) {
	if _, err := digestsOf([]string{"DFINE", ""}); err == nil {
		t.Error("a key set with a missing successor was committed anyway")
	}
}
