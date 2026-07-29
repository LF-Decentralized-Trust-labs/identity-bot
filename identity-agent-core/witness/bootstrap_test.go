package witness

import (
	"fmt"
	"testing"
)

// The bootstrap pool exists to cover one gap: a new identity has no contacts,
// and the moment it most needs witnessing — inception — is the moment it has
// nobody to ask. These tests hold it to that job and no larger one.

func TestAFreshIdentityGetsWitnesses(t *testing.T) {
	got := withBootstrap(nil, 3)
	if len(got) != 3 {
		t.Fatalf("a new identity with no contacts got %d witnesses, so nothing would receipt its inception", len(got))
	}
	for _, w := range got {
		if w.AID == "" || w.URL == "" {
			t.Fatalf("a bootstrap witness is missing an AID or URL: %+v", w)
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
	got := withBootstrap(contacts, 3)

	if len(got) != 3 {
		t.Fatalf("expected 3 witnesses, got %d", len(got))
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
	if len(got) != 3 {
		t.Fatalf("expected the gap still filled to 3 distinct witnesses, got %d", len(got))
	}
}

// Three operators, not six. Each host runs a witness and a watcher role under
// one identity, so anyone reasoning about independence should get three — and a
// threshold above that would have nothing to draw on.
func TestTheBootstrapPoolIsThreeDistinctOperators(t *testing.T) {
	pool := BootstrapPool()
	if len(pool) != 3 {
		t.Fatalf("expected 3 bootstrap witnesses, got %d", len(pool))
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
	for aid, n := range seen {
		if n > 200 {
			t.Errorf("operator %s took %d of 300 pairwise AIDs", aid, n)
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
