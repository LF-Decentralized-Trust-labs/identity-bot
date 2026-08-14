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

// Every pool that can be allocated from can also be read back from the same
// base.
//
// Two copies of these numbers would drift, and the failure is silent: a pool
// allocated from one base and read from another finds nothing, and reports an
// identity as belonging to somebody else rather than as missing. So there is
// one definition, and this checks that allocation actually uses it.
func TestAPoolIsAllocatedFromTheBaseItIsReadFrom(t *testing.T) {
	for _, pool := range []string{
		"contacts", "login", "machines", "delegated-identity",
		"invocation-log", "messaging-keys", "witnessing",
	} {
		base, err := PoolBase(pool)
		if err != nil {
			t.Fatalf("%s has no base: %v", pool, err)
		}
		s, serr := NewSQLiteStore(t.TempDir())
		if serr != nil {
			t.Skipf("data store unavailable: %v", serr)
		}
		got, err := s.AllocateNextRelationshipIndex(pool)
		if err != nil {
			t.Fatalf("%s: %v", pool, err)
		}
		if got != base {
			t.Errorf("%s allocates from %d but is read from %d", pool, got, base)
		}
	}
}

// A pool nobody has given a range to is refused by both, identically.
func TestAnUnknownPoolIsRefusedByBoth(t *testing.T) {
	if _, err := PoolBase("toaster"); err == nil {
		t.Error("PoolBase invented a range for a pool nobody assigned one to")
	}
	s, serr := NewSQLiteStore(t.TempDir())
	if serr != nil {
		t.Skipf("data store unavailable: %v", serr)
	}
	if _, err := s.AllocateNextRelationshipIndex("toaster"); err == nil {
		t.Error("allocation invented a range for a pool nobody assigned one to")
	}
}
