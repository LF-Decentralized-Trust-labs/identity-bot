package witness

import (
	"fmt"
	"testing"
)

// The bootstrap pool exists to cover one gap: a new identity has no contacts,
// and the moment it most needs witnessing — inception — is the moment it has
// nobody to ask. These tests hold it to that job and no larger one.

func TestAFreshIdentityGetsWitnesses(t *testing.T) {
	// Asks for more than the pool holds on purpose: what matters is that a new
	// identity is given everything available, not that some particular number
	// exists. The pool is expected to grow as operators join, and a test
	// asserting its size would fail on the day that happens.
	got := withBootstrap(nil, 3)
	if len(got) == 0 {
		t.Fatal("a new identity with no contacts got no witnesses, so nothing would " +
			"receipt its inception")
	}
	if len(got) > len(BootstrapPool()) {
		t.Fatalf("got %d witnesses from a pool of %d", len(got), len(BootstrapPool()))
	}
	for _, w := range got {
		if w.AID == "" || w.URL == "" {
			t.Fatalf("a bootstrap witness is missing an AID or URL: %+v", w)
		}
		// A witness that cannot be designated is not much use as a bootstrap:
		// the identity would reach it and then be unable to name it.
		if w.WitnessKey == "" {
			t.Fatalf("%s publishes no witness key, so it cannot be designated", w.AID)
		}
	}
}

// Contacts are the design; bootstrap is the stopgap. Somebody with enough
// contacts of their own must not be quietly leaning on us.
func TestContactsDisplaceBootstrap(t *testing.T) {
	contacts := []witnessTarget{
		{AID: "EFRIEND1", URL: "https://a.example"},
		{AID: "EFRIEND2", URL: "https://b.example"},
		{AID: "EFRIEND3", URL: "https://c.example"},
	}
	got := withBootstrap(contacts, 3)

	if len(got) != 3 {
		t.Fatalf("expected the contact list untouched, got %d", len(got))
	}
	for _, w := range got {
		for _, b := range BootstrapPool() {
			if w.AID == b.AID {
				t.Fatal("a bootstrap witness was added to an identity that already had enough contacts")
			}
		}
	}
}

// Partway there: keep every contact, top up the rest.
func TestBootstrapOnlyFillsTheGap(t *testing.T) {
	contacts := []witnessTarget{{AID: "EFRIEND1", URL: "https://a.example"}}
	want := 1 + len(BootstrapPool())
	got := withBootstrap(contacts, want)

	if len(got) != want {
		t.Fatalf("expected the contact plus the whole pool (%d), got %d", want, len(got))
	}
	if got[0].AID != "EFRIEND1" {
		t.Fatal("the contact was dropped or reordered — contacts come first, deliberately")
	}
}

// The same witness twice is one witness. Counting it twice would raise the
// threshold while adding no independent observer, which is worse than a smaller
// honest pool because it looks stronger than it is.
func TestAContactWhoIsAlsoBootstrapIsNotCountedTwice(t *testing.T) {
	pool := BootstrapPool()
	contacts := []witnessTarget{{AID: pool[0].AID, URL: pool[0].URL}}

	got := withBootstrap(contacts, 3)

	seen := map[string]int{}
	for _, w := range got {
		seen[w.AID]++
	}
	for aid, n := range seen {
		if n > 1 {
			t.Fatalf("%s appears %d times — the same witness twice is one witness", aid, n)
		}
	}
	if len(got) != len(seen) {
		t.Fatalf("got %d witnesses but only %d distinct ones", len(got), len(seen))
	}
}

// However many operators the pool holds, each must be a distinct one that can
// actually be designated. A host runs its witness and watcher roles under one
// identity, so anybody reasoning about independence should count identities and
// not endpoints — a threshold above that count would have nothing to draw on.
func TestTheBootstrapPoolIsDistinctDesignatableOperators(t *testing.T) {
	pool := BootstrapPool()
	if len(pool) == 0 {
		t.Fatal("the bootstrap pool is empty, so a new identity has nobody to be witnessed by")
	}
	for _, w := range pool {
		// Non-transferable, because a witness identifier IS the key its
		// receipts verify against. A transferable one would mean resolving a
		// key log per receipt, and would orphan its own receipts on rotation.
		if len(w.WitnessKey) != 44 || w.WitnessKey[0] != 'B' {
			t.Fatalf("%s has witness key %q, which is not a non-transferable identifier",
				w.URL, w.WitnessKey)
		}
	}
	seen := map[string]bool{}
	for _, w := range pool {
		if seen[w.AID] {
			t.Fatalf("%s is listed twice — that is one witness wearing two names", w.AID)
		}
		seen[w.AID] = true
	}
}

// Asking for none must yield none, rather than silently enrolling us.
func TestAskingForNoWitnessesAddsNone(t *testing.T) {
	if got := withBootstrap(nil, 0); len(got) != 0 {
		t.Fatalf("expected none, got %d", len(got))
	}
}

// A pairwise AID with no commercial contacts still gets an observer. Before
// this, it got none — the eligibility gate correctly refuses contact witnesses
// on a pairwise AID, which on a fresh identity means refusing everything.
func TestPairwiseAlwaysGetsOneWitness(t *testing.T) {
	w, ok := oneBootstrapFor("EPairwiseSomeoneJustMet")
	if !ok {
		t.Fatal("a pairwise AID was left with no witness at all")
	}
	if !w.Commercial {
		t.Errorf("a pairwise witness must be commercial, got a contact: %s", w.AID)
	}
}

// The same AID must always pick the same witness, or a receipt can never be
// chased: the event goes to one place and the follow-up looks somewhere else.
func TestPairwiseWitnessIsStableForAnAID(t *testing.T) {
	const aid = "EPairwiseStableCheck"
	first, _ := oneBootstrapFor(aid)
	for i := 0; i < 50; i++ {
		again, _ := oneBootstrapFor(aid)
		if again.AID != first.AID {
			t.Fatalf("same AID chose two witnesses: %s then %s", first.AID, again.AID)
		}
	}
}

// Different pairwise AIDs must not all land on one operator. If they did, that
// operator could reassemble the contact graph from its own logs — the exact
// correlation separate pairwise AIDs exist to prevent.
func TestPairwiseWitnessesSpreadAcrossThePool(t *testing.T) {
	seen := map[string]int{}
	for i := 0; i < 300; i++ {
		w, _ := oneBootstrapFor(fmt.Sprintf("EPairwiseContact%d", i))
		seen[w.AID]++
	}
	if len(seen) != len(BootstrapPool()) {
		t.Fatalf("expected all %d operators to be used, only %d were: %v",
			len(BootstrapPool()), len(seen), seen)
	}
	// Not a statistical test — just that no operator takes nearly everything.
	//
	// Only meaningful once there is more than one operator to spread across.
	// With a single-operator pool every pairwise AID goes to it by necessity,
	// and asserting otherwise would be asserting that the pool is bigger than
	// it is. This check comes back on its own when a second operator is added.
	if len(BootstrapPool()) > 1 {
		limit := 300 - 300/(2*len(BootstrapPool()))
		for aid, n := range seen {
			if n > limit {
				t.Errorf("operator %s took %d of 300 pairwise AIDs", aid, n)
			}
		}
	}
}

// The policy, stated as a test so relaxing it has to be deliberate.
//
// No number of contact witnesses makes a non-commercial one acceptable on a
// pairwise AID. Everywhere else contacts are meant to displace commercial
// witnesses over time; here they never do, because on a pairwise AID the
// contacts are the thing that leaks. Witness lists are public, so a
// distinctive set shared between two pairwise AIDs links them to one person.
func TestPeersNeverDisplaceCommercialOnPairwise(t *testing.T) {
	for _, commercial := range []bool{true, false} {
		got := ContactWitnessAllowedForAID(AidKindPairwise, commercial)
		if got != commercial {
			t.Errorf("pairwise + commercial=%v: allowed=%v, want %v",
				commercial, got, commercial)
		}
	}
	// A root AID is the opposite case and must stay that way, or peer
	// witnessing has no path to displace anything anywhere.
	if !ContactWitnessAllowedForAID(AidKindRoot, false) {
		t.Error("a root AID must accept contact witnesses — that is the design")
	}
}
