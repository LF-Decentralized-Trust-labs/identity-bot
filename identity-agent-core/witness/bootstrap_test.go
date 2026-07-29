package witness

import "testing"

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
