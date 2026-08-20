package recovery

import (
	"bytes"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"identity-agent-core/backup"
)

// aHoldingOf sets up a machine holding one share for somebody else's identity.
func aHoldingOf(t *testing.T, policy HoldingPolicy) (*Holder, Holding, backup.SealedShare, []byte) {
	t.Helper()
	seed := make([]byte, 64)
	rand.Read(seed)
	priv, pub, err := backup.DeriveSealKeypair(seed)
	if err != nil {
		t.Fatal(err)
	}

	share := make([]byte, 32)
	rand.Read(share)
	eph, wrapped, nonce, err := backup.SealBEK(pub, share)
	if err != nil {
		t.Fatal(err)
	}
	sealed := backup.SealedShare{
		HolderID:        "EThisHolder",
		EphemeralPubB64: backup.EncodeB64(eph),
		WrappedB64:      backup.EncodeB64(wrapped),
		NonceB64:        backup.EncodeB64(nonce),
	}
	holding := Holding{
		IdentityAID:   "EPairwiseForThisRelationship",
		HolderID:      "EThisHolder",
		PrivateKeyB64: backup.EncodeB64(priv),
		Policy:        policy,
	}
	return &Holder{DataDir: t.TempDir()}, holding, sealed, share
}

// The wait cannot be skipped by asking again.
//
// This is the property the whole holder side exists for. A waiting period is
// only a protection if whoever is waiting cannot move the clock, and the
// request cannot be allowed to say when the recovery began — an attacker would
// say last week. So the holder writes down when it was FIRST asked and refuses
// until the wait has passed since then.
//
// Asking repeatedly is exactly what an impatient attacker does, so asking must
// not restart, extend, or satisfy anything.
func TestAskingAgainDoesNotMoveTheClock(t *testing.T) {
	h, holding, sealed, want := aHoldingOf(t, HoldingPolicy{WaitHours: 48})
	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

	// Asked repeatedly across the first day.
	for i := 0; i < 5; i++ {
		_, err := h.Release(holding, sealed, start.Add(time.Duration(i)*time.Hour))
		var held *ErrHeldForWait
		if !errors.As(err, &held) {
			t.Fatalf("ask %d was not held: %v", i, err)
		}
	}

	// Still held one minute before the wait is up, counted from the FIRST ask
	// rather than the most recent.
	_, err := h.Release(holding, sealed, start.Add(48*time.Hour-time.Minute))
	if !errors.As(err, new(*ErrHeldForWait)) {
		t.Fatalf("released a minute early: %v", err)
	}

	got, err := h.Release(holding, sealed, start.Add(48*time.Hour+time.Minute))
	if err != nil {
		t.Fatalf("still held after the wait had passed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the share that came back is not the one that was sealed")
	}
}

// The clock survives the holder being restarted.
//
// A wait kept only in memory is a wait an attacker skips by getting the
// machine restarted, which is not a difficult thing to arrange.
func TestTheClockSurvivesARestart(t *testing.T) {
	h, holding, sealed, _ := aHoldingOf(t, HoldingPolicy{WaitHours: 48})
	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

	if _, err := h.Release(holding, sealed, start); !errors.As(err, new(*ErrHeldForWait)) {
		t.Fatalf("the first ask was not held: %v", err)
	}

	// A different Holder over the same directory is what the next process is.
	restarted := &Holder{DataDir: h.DataDir}
	if _, err := restarted.Release(holding, sealed, start.Add(time.Hour)); !errors.As(err, new(*ErrHeldForWait)) {
		t.Fatalf("a restart reset the wait: %v", err)
	}
	if _, err := restarted.Release(holding, sealed, start.Add(49*time.Hour)); err != nil {
		t.Fatalf("the wait did not carry across the restart: %v", err)
	}
}

// The owner is told the first time somebody asks, and told once.
//
// This is the property no other configuration has: a theft becomes an event
// the owner hears about rather than one they never do. It fires on the first
// ask, before any wait, because the whole value is in the owner learning early
// enough to act.
func TestTheOwnerIsToldTheFirstTimeSomebodyAsks(t *testing.T) {
	h, holding, sealed, _ := aHoldingOf(t, HoldingPolicy{WaitHours: 48})
	var told int
	var toldFirst bool
	h.Notify = func(aid string, first bool) {
		told++
		toldFirst = first
	}
	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

	for i := 0; i < 4; i++ {
		h.Release(holding, sealed, start.Add(time.Duration(i)*time.Hour))
	}
	if told != 1 {
		t.Fatalf("the owner was told %d times; asking repeatedly must not become a way to flood them", told)
	}
	if !toldFirst {
		t.Fatal("the notification did not say this was the first ask")
	}
}

// A holder that cannot notify still records and still waits.
func TestAHolderWithNowhereToNotifyStillWaits(t *testing.T) {
	h, holding, sealed, _ := aHoldingOf(t, HoldingPolicy{WaitHours: 48})
	h.Notify = nil
	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

	if _, err := h.Release(holding, sealed, start); !errors.As(err, new(*ErrHeldForWait)) {
		t.Fatalf("a holder with no way to notify did not wait: %v", err)
	}
}

// Where a person must decide, time alone does not release the share.
func TestTimePassingIsNotApproval(t *testing.T) {
	h, holding, sealed, want := aHoldingOf(t, HoldingPolicy{WaitHours: 1, RequireApproval: true})
	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

	if _, err := h.Release(holding, sealed, start); !errors.As(err, new(*ErrHeldForWait)) {
		t.Fatal("expected the wait first")
	}
	_, err := h.Release(holding, sealed, start.Add(2*time.Hour))
	if !errors.As(err, new(*ErrNeedsApproval)) {
		t.Fatalf("the wait passing released a share a person was meant to approve: %v", err)
	}

	if err := h.Approve(holding.IdentityAID, holding.HolderID, start.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := h.Release(holding, sealed, start.Add(4*time.Hour))
	if err != nil {
		t.Fatalf("approved and still refused: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the wrong share came back")
	}
}

// Nobody can approve a recovery that has not been asked about.
//
// Otherwise somebody with access to this holder could pre-approve their own
// future request and walk straight past the gate.
func TestARecoveryNobodyHasAskedAboutCannotBeApproved(t *testing.T) {
	h, _, _, _ := aHoldingOf(t, HoldingPolicy{RequireApproval: true})
	err := h.Approve("ESomeIdentity", "EThisHolder", time.Now())
	if err == nil {
		t.Fatal("a recovery nobody had asked about was approved in advance")
	}
}

// A share sealed to somebody else is refused.
func TestAShareSealedToAnotherHolderIsRefused(t *testing.T) {
	h, holding, _, _ := aHoldingOf(t, HoldingPolicy{})
	_, other, otherSealed, _ := aHoldingOf(t, HoldingPolicy{})
	_ = other

	// Addressed to this holder by name, but sealed to a different key.
	otherSealed.HolderID = holding.HolderID
	if _, err := h.Release(holding, otherSealed, time.Now()); err == nil {
		t.Fatal("a share sealed to another holder was opened")
	}
}

// A request naming a different holder is refused before anything is decrypted.
func TestAShareAddressedElsewhereIsRefused(t *testing.T) {
	h, holding, sealed, _ := aHoldingOf(t, HoldingPolicy{})
	sealed.HolderID = "ESomebodyElse"
	_, err := h.Release(holding, sealed, time.Now())
	if err == nil {
		t.Fatal("a share addressed to another holder was processed")
	}
}

// Being asked is recorded whatever the outcome.
//
// A refusal that leaves no trace is a refusal nobody learns from, and the
// record of having been asked is the thing that tells an owner somebody tried.
func TestBeingAskedIsRecordedEvenWhenRefused(t *testing.T) {
	h, holding, sealed, _ := aHoldingOf(t, HoldingPolicy{WaitHours: 48})
	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

	h.Release(holding, sealed, start)
	h.Release(holding, sealed, start.Add(time.Hour))

	asked, err := h.WhatHasBeenAsked()
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 {
		t.Fatalf("expected one identity asked about, got %d", len(asked))
	}
	if asked[0].Times != 2 {
		t.Fatalf("asked twice, recorded %d times", asked[0].Times)
	}
	if asked[0].ReleasedAt != "" {
		t.Fatal("a refused request was recorded as released")
	}
}

// A holder with no waiting period releases, and that is a real choice.
func TestAHolderWithNoWaitReleasesImmediately(t *testing.T) {
	h, holding, sealed, want := aHoldingOf(t, HoldingPolicy{})
	got, err := h.Release(holding, sealed, time.Now())
	if err != nil {
		t.Fatalf("a holder with no policy refused: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the wrong share came back")
	}
}

// A recovery that already happened must not disarm this holder forever.
//
// The record used to be keyed by identity, with the first-asked timestamp
// never touched again and the approval never cleared. So an owner who
// recovered once — or ran a drill — left the gates permanently open: years
// later, a thief with a fresh backup and the words was released instantly,
// with no wait, no fresh approval, and no notification, because this holder
// had "already been asked about" that identity.
func TestASecondRecoveryFacesTheGatesAgain(t *testing.T) {
	h, holding, first, _ := aHoldingOf(t, HoldingPolicy{WaitHours: 48, RequireApproval: true})
	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

	// One legitimate recovery, all the way through.
	h.Release(holding, first, start)
	if err := h.Approve(holding.IdentityAID, holding.HolderID, start.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Release(holding, first, start.Add(49*time.Hour)); err != nil {
		t.Fatalf("the legitimate recovery did not complete: %v", err)
	}

	// Years later, a different backup of the same identity — a new archive
	// means a new sealing, which is what makes it a different attempt.
	newShare := make([]byte, 32)
	rand.Read(newShare)
	_, second := reSealTo(t, holding, newShare)

	var told int
	h.Notify = func(string, bool) { told++ }

	much := start.Add(10 * 365 * 24 * time.Hour)
	_, err := h.Release(holding, second, much)
	if !errors.As(err, new(*ErrHeldForWait)) {
		t.Fatalf("a second recovery skipped the waiting period entirely: %v", err)
	}
	if told != 1 {
		t.Fatalf("the owner was told %d times about a brand-new recovery", told)
	}

	// And the approval from years ago is not spent on this one.
	_, err = h.Release(holding, second, much.Add(49*time.Hour))
	if !errors.As(err, new(*ErrNeedsApproval)) {
		t.Fatalf("an approval given years ago released a share today: %v", err)
	}
}

// Asks are not lost when several arrive together.
func TestConcurrentAsksAreAllRecorded(t *testing.T) {
	// A wait, so none of them releases and rearms — this is about the count.
	h, holding, sealed, _ := aHoldingOf(t, HoldingPolicy{WaitHours: 48})
	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.Release(holding, sealed, start)
		}()
	}
	wg.Wait()

	asked, err := h.WhatHasBeenAsked()
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 {
		t.Fatalf("expected one record, got %d", len(asked))
	}
	if asked[0].Times != 8 {
		t.Fatalf("eight asks arrived together and %d were recorded; a lost update "+
			"means the count an owner is shown is wrong", asked[0].Times)
	}
}

// reSealTo seals a share to a holding's own key, for building a second attempt.
func reSealTo(t *testing.T, holding Holding, share []byte) ([]byte, backup.SealedShare) {
	t.Helper()
	priv, err := backup.DecodeB64(holding.PrivateKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := backup.PublicFromPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	eph, wrapped, nonce, err := backup.SealBEK(pub, share)
	if err != nil {
		t.Fatal(err)
	}
	return share, backup.SealedShare{
		HolderID:        holding.HolderID,
		EphemeralPubB64: backup.EncodeB64(eph),
		WrappedB64:      backup.EncodeB64(wrapped),
		NonceB64:        backup.EncodeB64(nonce),
	}
}
