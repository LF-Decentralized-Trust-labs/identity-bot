package server

import (
	"encoding/json"
	"reflect"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keymath"
	"identity-agent-core/store"
)

// keymath, which the app runs, gives exactly what the core's own paths give
// for the same child seeds: the post-quantum commitment a founding or rotation
// makes, and the messaging keyset a founding anchors.
func TestKeymathAgreesWithTheCore(t *testing.T) {
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
	next, _ := backup.DerivePairwiseSeed(root, 0, 1)
	nextKey := verkeyOf(next)
	for gen := 0; gen < 3; gen++ {
		digests, _ := s.postQuantumPreRotationAt(nextKey, gen)
		if len(digests) != 2 {
			t.Fatalf("generation %d: the core made no post-quantum commitment", gen)
		}
		child, err := backup.DerivePairwiseSeed(root, postQuantumPreRotationContact, postQuantumPreRotationKey+gen)
		if err != nil {
			t.Fatal(err)
		}
		pq, err := keymath.PostQuantumNextKey(child)
		if err != nil {
			t.Fatal(err)
		}
		if pq.Digest != digests[1] {
			t.Fatalf("generation %d: keymath commits to %s and the core to %s", gen, pq.Digest, digests[1])
		}
		if classical, _ := iacrypto.NextKeyDigest(nextKey); classical != digests[0] {
			t.Fatalf("generation %d: the classical commitment differs", gen)
		}
	}

	for _, idx := range []int{1, 7} {
		ks, err := s.keysAtIndex(root, "", idx)
		if err != nil {
			t.Fatal(err)
		}
		kemPub, _ := ks.KemPub.MarshalBinary()
		dsaPub, _ := ks.DsaPub.MarshalBinary()
		want, err := iacrypto.KeySetAnchor(ks.XPub[:], kemPub, ks.EdPub, dsaPub)
		if err != nil {
			t.Fatal(err)
		}
		child, _ := backup.DerivePairwiseSeed(root, idx, 0)
		got, err := keymath.MessagingKeySet(child)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(want)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("branch %d: keymath anchors %s and the core %s", idx, a, b)
		}
	}
}
