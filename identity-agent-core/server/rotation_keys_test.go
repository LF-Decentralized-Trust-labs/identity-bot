package server

import (
	"crypto/ed25519"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/store"
)

// Finding an identity's own rotation key again.
//
// The defect this fixes: pairing derived a key, used it, cleared the seed and
// recorded the resulting identifier — but never recorded WHERE the key came
// from. The identity existed, worked, and could never rotate, because the one
// key a rotation must include was a derivation nobody could repeat. There was
// no error until somebody tried, and by then the identity was founded.

// foundLikePairingDoes creates an identity the way pairing does: keys derived
// from the root seed at an index, the successor's digest committed, and the
// index written down.
func foundLikePairingDoes(t *testing.T, s *CoreServer, index int) (current, next string) {
	t.Helper()
	rootSeed, err := ensureRootSeed(s.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	pub := func(keyIndex int) string {
		seed, derr := backup.DerivePairwiseSeed(rootSeed, index, keyIndex)
		if derr != nil {
			t.Fatal(derr)
		}
		return iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	}
	current, next = pub(0), pub(1)

	if err := s.DataStore.SaveIdentity(store.IdentityState{
		AID: "EORG", PublicKey: current,
		// What the inception committed to: the digest of the successor.
		NextKeyDigest:   iacrypto.Blake3QB64Must([]byte(next)),
		Created:         "2026-08-01T00:00:00Z",
		EventCount:      1,
		DerivationIndex: index,
		KeyGeneration:   0,
	}); err != nil {
		t.Fatal(err)
	}
	return current, next
}

// The property everything rests on: the derived key is the one the identity
// already committed to. If it is not, no verifier accepts the rotation.
func TestTheDerivedKeyIsTheOneTheIdentityCommittedTo(t *testing.T) {
	s := serverWithIdentity(t, "EORG")
	_, committedNext := foundLikePairingDoes(t, s, 7)

	keys, err := s.ownRotationKeys()
	if err != nil {
		t.Fatalf("this identity could not find its own rotation key: %v", err)
	}
	if keys.Current != committedNext {
		t.Errorf("derived %q, but the identity committed to %q", keys.Current, committedNext)
	}
	if keys.Next == "" || keys.Next == keys.Current {
		t.Errorf("the successor is missing or the same key: %q", keys.Next)
	}
}

// The index is what makes it findable. Recording the wrong one produces a key
// the identity never committed to, and a rotation built on it would be refused
// — after a ceremony had already collected everybody's signatures.
func TestAWrongDerivationIndexIsCaughtBeforeRotating(t *testing.T) {
	s := serverWithIdentity(t, "EORG")
	foundLikePairingDoes(t, s, 7)

	identity, _ := s.DataStore.GetIdentity()
	identity.DerivationIndex = 8 // the branch this identity did not come from
	if err := s.DataStore.SaveIdentity(*identity); err != nil {
		t.Fatal(err)
	}

	if _, err := s.ownRotationKeys(); err == nil {
		t.Fatal("a key that does not match the recorded commitment was accepted")
	}
}

// Rotating twice must derive from a different place the second time, or the
// identity would rotate into the key it already used.
func TestEachRotationDerivesFromFurtherAlong(t *testing.T) {
	s := serverWithIdentity(t, "EORG")
	foundLikePairingDoes(t, s, 7)

	first, err := s.ownRotationKeys()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.advanceKeyGeneration(first.Current,
		iacrypto.Blake3QB64Must([]byte(first.Next))); err != nil {
		t.Fatal(err)
	}

	second, err := s.ownRotationKeys()
	if err != nil {
		t.Fatalf("could not derive a second rotation: %v", err)
	}
	if second.Current == first.Current {
		t.Error("the second rotation reuses the first rotation's key")
	}
	// And it is the key the first rotation committed to.
	if second.Current != first.Next {
		t.Errorf("the second rotation derives %q, but the first committed to %q",
			second.Current, first.Next)
	}
}

// The generation advances only once the rotation is accepted. Advancing first
// and failing would leave the identity believing it had moved on while its log
// said otherwise, and every later rotation would derive a key its own events do
// not commit to.
func TestTheGenerationRecordsWhereTheKeysActuallyMovedTo(t *testing.T) {
	s := serverWithIdentity(t, "EORG")
	foundLikePairingDoes(t, s, 7)

	before, _ := s.DataStore.GetIdentity()
	if before.KeyGeneration != 0 {
		t.Fatalf("a fresh identity starts at generation %d", before.KeyGeneration)
	}

	keys, _ := s.ownRotationKeys()
	s.advanceKeyGeneration(keys.Current, iacrypto.Blake3QB64Must([]byte(keys.Next)))

	after, _ := s.DataStore.GetIdentity()
	if after.KeyGeneration != 1 {
		t.Errorf("generation is %d after one rotation", after.KeyGeneration)
	}
	if after.PublicKey != keys.Current {
		t.Error("the identity's current key was not updated to what it rotated into")
	}
}

// It has to survive a restart, because a rotation may happen years after
// founding — that is the entire point of recording it rather than holding it in
// memory, which is what the previous version did.
func TestTheDerivationSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := &CoreServer{DataDir: dir, DataStore: ds}
	_, committedNext := foundLikePairingDoes(t, s, 42)

	reopened, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	restarted := &CoreServer{DataDir: dir, DataStore: reopened}

	keys, err := restarted.ownRotationKeys()
	if err != nil {
		t.Fatalf("after a restart the identity could not find its own key: %v", err)
	}
	if keys.Current != committedNext {
		t.Error("the derivation did not survive the restart")
	}
}

// The bug that fell out of building the above, and the reason it hid so well.
//
// The identity table has no primary key, so ON CONFLICT(rowid) never fired and
// every SaveIdentity INSERTED. GetIdentity reads one row, so an agent went on
// reading its original identity for ever while each update piled up behind it,
// unread. Nothing failed — it simply kept answering with the state it started
// in.
//
// Rotation is what exposed it. An identity that advanced its keys would keep
// reporting the ones it began with, and derive every future rotation from the
// wrong generation.
func TestSavingTheIdentityUpdatesItRatherThanAddingAnother(t *testing.T) {
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	for i, key := range []string{"DFIRST", "DSECOND", "DTHIRD"} {
		if err := ds.SaveIdentity(store.IdentityState{
			AID: "EORG", PublicKey: key, NextKeyDigest: "EDIGEST",
			Created: "2026-08-01T00:00:00Z", EventCount: i + 1,
			DerivationIndex: 7, KeyGeneration: i,
		}); err != nil {
			t.Fatal(err)
		}
	}

	got, err := ds.GetIdentity()
	if err != nil || got == nil {
		t.Fatalf("no identity: %v", err)
	}
	if got.PublicKey != "DTHIRD" {
		t.Errorf("reads %q — an update was written and never read", got.PublicKey)
	}
	if got.KeyGeneration != 2 {
		t.Errorf("generation reads %d, not the one last written", got.KeyGeneration)
	}
}
