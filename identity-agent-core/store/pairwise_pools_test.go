package store

import "testing"

// Two pools must never hand out the same index.
//
// Every pairwise key is derived from one root seed and an index, so two pools
// starting at the same number produce the SAME KEY for unrelated relationships
// — and two parties holding keys derived from one secret can discover they are
// the same person, which is exactly what a pairwise identifier prevents.
//
// This is not hypothetical. Adding the machines pool without its own range
// immediately minted an identifier identical to one already in use.
func TestPoolsDoNotHandOutTheSameIndex(t *testing.T) {
	s, err := NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Skipf("store unavailable: %v", err)
	}
	defer s.Close()

	seen := map[int]string{}
	for _, pool := range []string{"contacts", "login", "machines"} {
		for i := 0; i < 3; i++ {
			idx, err := s.AllocateNextRelationshipIndex(pool)
			if err != nil {
				t.Fatalf("allocating in %s: %v", pool, err)
			}
			if other, clash := seen[idx]; clash {
				t.Fatalf("pool %q and pool %q both allocated index %d, so both derive "+
					"the SAME key — two relationships that must never be linkable "+
					"would share a secret", pool, other, idx)
			}
			seen[idx] = pool
		}
	}
}

// A new pool that nobody gave a range to must not silently start at 1 and
// collide with contacts.
func TestAnUnknownPoolDoesNotSilentlyShareTheContactsRange(t *testing.T) {
	s, err := NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Skipf("store unavailable: %v", err)
	}
	defer s.Close()

	contact, cErr := s.AllocateNextRelationshipIndex("contacts")
	if cErr != nil {
		t.Fatal(cErr)
	}
	_ = contact
	if _, oErr := s.AllocateNextRelationshipIndex("something-new"); oErr == nil {
		t.Fatal("a pool nobody assigned a range to was allowed, and it starts where " +
			"contacts starts — so its first identity would share a key with the first " +
			"contact, silently and undetectably. Refusing is the point")
	}
}
