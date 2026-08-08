package server

import (
	"testing"

	"identity-agent-core/store"
)

// Nothing checked must never read as checked. On a phone there is no engine to
// check with, and an address that publishes no history gives nothing to check —
// neither of which is the same as checking and finding it sound.
func TestNothingCheckedIsNotReportedAsVerified(t *testing.T) {
	s := newExchangeTestServer(t) // no KeriDriver, i.e. a phone
	_ = s.DataStore.SaveContact(store.ContactRecord{
		AID: "ETHEIRS", PublicKey: "DGwUXQpxNXKlbEwLLL0zAFTMlWlBEyAKWpEfLGxWEIYd",
		OobiURL: "https://example.invalid/oobi",
	})

	got := s.contactKeyForUse("ETHEIRS")
	if got.State != kelUnchecked {
		t.Fatalf("a device with no engine reported %q, want %q", got.State, kelUnchecked)
	}
	if got.State == kelVerifiedNow {
		t.Fatal("nothing was checked and it reported verified")
	}
	if got.Reason == "" {
		t.Error("no reason was given for why nothing was checked")
	}
	// It still hands back the key it has, so a caller can decide what an
	// unchecked key is worth rather than being left with nothing.
	if got.Key == "" {
		t.Error("no key was returned at all")
	}
}

// Somebody this agent has never resolved cannot be checked and must not be
// treated as though they had been.
func TestAStrangerIsUnchecked(t *testing.T) {
	s := newExchangeTestServer(t)
	got := s.contactKeyForUse("ENOBODY")
	if got.State != kelUnchecked {
		t.Fatalf("a stranger reported %q", got.State)
	}
	if got.Key != "" {
		t.Error("a key was returned for somebody with no record")
	}
}

// The result is cached briefly so one interaction does not re-fetch repeatedly,
// but the cache must be short enough that this is freshness rather than the old
// once-and-never-again behaviour under a new name.
func TestTheCheckIsFreshRatherThanRemembered(t *testing.T) {
	if kelCheckFreshness > 15*60*1e9 {
		t.Fatalf("the check is cached for %v, which is long enough to be the old behaviour", kelCheckFreshness)
	}
}

// The three states must stay distinct. Collapsing "could not check" into
// either of the others is exactly the bug this exists to prevent.
func TestTheThreeStatesAreDistinct(t *testing.T) {
	seen := map[kelCheck]bool{}
	for _, st := range []kelCheck{kelVerifiedNow, kelFailed, kelUnchecked} {
		if st == "" {
			t.Error("a state has no value")
		}
		if seen[st] {
			t.Errorf("%q is used for more than one state", st)
		}
		seen[st] = true
	}
}
