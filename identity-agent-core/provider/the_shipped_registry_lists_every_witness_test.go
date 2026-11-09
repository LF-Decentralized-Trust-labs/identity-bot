package provider

import "testing"

// The shipped registry lists all three witnesses, and exactly one of them —
// witness1 — is marked the default a new root identity designates. A listed
// witness must stay resolvable (an identity founded with several of them
// reaches all of them), while the inception default is chosen by the mark,
// never by listing order.
func TestTheShippedRegistryListsEveryWitnessAndMarksWitness1Default(t *testing.T) {
	r := Load(t.TempDir())
	p, ok := r.Get("grapeid.org")
	if !ok {
		t.Fatal("the shipped registry has no grapeid.org entry")
	}
	witnesses := p.EndpointsFor(CapabilityWitness)
	want := []string{
		"https://witness1.grapeid.org",
		"https://witness2.grapeid.org",
		"https://witness3.grapeid.org",
	}
	if len(witnesses) != len(want) {
		t.Fatalf("the shipped registry lists %d witnesses, want %d: %+v", len(witnesses), len(want), witnesses)
	}
	byURL := map[string]Endpoint{}
	for _, e := range witnesses {
		byURL[e.URL] = e
		if e.AID == "" {
			t.Errorf("witness %s lists no identifier", e.URL)
		}
	}
	for _, u := range want {
		if _, ok := byURL[u]; !ok {
			t.Errorf("witness %s is not listed", u)
		}
	}
	defaults := 0
	for _, e := range witnesses {
		if e.Default {
			defaults++
			if e.URL != "https://witness1.grapeid.org" {
				t.Errorf("%s is marked default, want witness1", e.URL)
			}
		}
	}
	if defaults != 1 {
		t.Fatalf("%d witnesses are marked default, want exactly one (witness1)", defaults)
	}
}
