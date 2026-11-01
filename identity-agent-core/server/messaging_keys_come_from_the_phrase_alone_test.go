package server

import (
	"bytes"
	"os"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/keymath"
	"identity-agent-core/store"
)

// A new identity's messaging keys come from the fixed branch, so they come
// back from the phrase alone, with no record of a branch; they are the keyset
// keymath gives the app for the same child seed. An identity whose record
// names an allocated branch keeps it.
func TestMessagingKeysComeFromThePhraseAlone(t *testing.T) {
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: dir, DataStore: ds, EventHub: NewEventHub()}
	endsItsBackgroundWork(t, s)
	root, err := ensureRootSeed(dir)
	if err != nil {
		t.Fatal(err)
	}

	first, idx, err := s.deriveMessagingKeys("")
	if err != nil || idx != 0 {
		t.Fatalf("a new identity's messaging keys: branch %d, %v", idx, err)
	}
	if err := os.Remove(s.messagingKeyPath()); err != nil {
		t.Fatal(err)
	}
	again, _, err := s.deriveMessagingKeys("")
	if err != nil || !bytes.Equal(first.EdPub, again.EdPub) || first.XPub != again.XPub {
		t.Fatalf("with the record gone, the keys did not come back from the phrase: %v", err)
	}
	child, _ := backup.DerivePairwiseSeed(root, backup.MessagingBranch, 0)
	anchor, err := keymath.MessagingKeySet(child)
	if err != nil {
		t.Fatal(err)
	}
	sa, _ := anchor["sa"].([]string)
	if len(sa) == 0 || sa[0] != verkeyOf(first.EdPriv.Seed()) {
		t.Fatalf("the app's keymath anchors a different keyset: %v", anchor)
	}

	if err := s.recordMessagingKeyIndex("", 5); err != nil {
		t.Fatal(err)
	}
	legacy, idx, err := s.deriveMessagingKeys("")
	if err != nil || idx != 5 || bytes.Equal(legacy.EdPub, first.EdPub) {
		t.Fatalf("a recorded branch did not win: branch %d, %v", idx, err)
	}
}
