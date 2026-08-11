package provider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testRegistry(t *testing.T, providers ...Provider) *Registry {
	t.Helper()
	r := &Registry{providers: map[string]*Provider{}}
	for i := range providers {
		p := providers[i]
		if err := r.Add(p, "test"); err != nil {
			t.Fatalf("add %s: %v", p.ID, err)
		}
	}
	return r
}

func operator(id string, caps ...Capability) Provider {
	p := Provider{ID: id, Operator: id}
	for _, c := range caps {
		p.Endpoints = append(p.Endpoints, Endpoint{Capability: c, URL: "https://" + string(c) + "." + id})
	}
	return p
}

// The point of the whole design: an operator already doing something for this
// identity should not be handed a second job while an unused one exists.
func TestAnUnusedOperatorIsPreferred(t *testing.T) {
	r := testRegistry(t,
		operator("alpha.test", CapabilityRelay, CapabilityWitness),
		operator("beta.test", CapabilityWitness),
	)
	s := NewSelector(r)

	relay, err := s.Choose(CapabilityRelay)
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	if relay.Provider.ID != "alpha.test" {
		t.Fatalf("only alpha offers relay, got %s", relay.Provider.ID)
	}

	witness, err := s.Choose(CapabilityWitness)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	if witness.Provider.ID != "beta.test" {
		t.Errorf("witness went to %s, which already runs the relay — an unused operator was available",
			witness.Provider.ID)
	}
}

// Scarcity must degrade the preference rather than empty the list. Refusing to
// select would leave an identity with no relay at all, which is far worse than
// one operator knowing two things.
func TestASingleOperatorIsStillUsedWhenItIsTheOnlyOne(t *testing.T) {
	r := testRegistry(t, operator("only.test", CapabilityRelay, CapabilityWitness))
	s := NewSelector(r)

	if _, err := s.Choose(CapabilityRelay); err != nil {
		t.Fatalf("relay: %v", err)
	}
	witness, err := s.Choose(CapabilityWitness)
	if err != nil {
		t.Fatalf("a sole operator must still be usable, got: %v", err)
	}
	if witness.Provider.ID != "only.test" {
		t.Fatalf("unexpected provider %s", witness.Provider.ID)
	}
	// Reused is a materially different answer from freely chosen, and the
	// reasoning has to say so.
	if witness.Why == "" || !strings.Contains(witness.Why, "reused despite preference") {
		t.Errorf("a reused operator should be reported as such, got: %q", witness.Why)
	}
}

// Witness and mailbox on one operator means a single outage removes both the
// way to reach somebody and the way to find out where they went.
func TestWitnessAndMailboxAreSeparatedWhenPossible(t *testing.T) {
	r := testRegistry(t,
		operator("alpha.test", CapabilityWitness, CapabilityMailbox),
		operator("beta.test", CapabilityMailbox),
	)
	s := NewSelector(r)

	if _, err := s.Choose(CapabilityWitness); err != nil {
		t.Fatalf("witness: %v", err)
	}
	mailbox, err := s.Choose(CapabilityMailbox)
	if err != nil {
		t.Fatalf("mailbox: %v", err)
	}
	if mailbox.Provider.ID == "alpha.test" {
		t.Error("the mailbox went to the same operator as the witness — the anchor and its fallback " +
			"now share one failure domain")
	}
}

// A capability nobody offers is a refusal, not an empty selection that looks
// like a decision.
func TestChoosingSomethingNobodyOffersFails(t *testing.T) {
	r := testRegistry(t, operator("alpha.test", CapabilityRelay))
	if _, err := NewSelector(r).Choose(CapabilityWatcher); err == nil {
		t.Fatal("expected a refusal when no operator offers the capability")
	}
}

// Reserve exists so a restart does not forget prior choices and re-concentrate
// everything onto one operator.
func TestPriorChoicesAreHonouredAfterAReserve(t *testing.T) {
	r := testRegistry(t,
		operator("alpha.test", CapabilityRelay, CapabilityWitness),
		operator("beta.test", CapabilityWitness),
	)
	s := NewSelector(r)
	s.Reserve("alpha.test", CapabilityRelay) // as if read back from storage

	witness, err := s.Choose(CapabilityWitness)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	if witness.Provider.ID != "beta.test" {
		t.Errorf("a reserved prior choice was ignored; witness went to %s", witness.Provider.ID)
	}
}

func TestDiversityReportsConcentration(t *testing.T) {
	r := testRegistry(t, operator("only.test", CapabilityRelay, CapabilityWitness, CapabilityMailbox))
	s := NewSelector(r)
	s.Choose(CapabilityRelay)
	s.Choose(CapabilityWitness)
	s.Choose(CapabilityMailbox)

	operators, busiest := s.Diversity()
	if operators != 1 || busiest != 3 {
		t.Errorf("expected 1 operator holding 3 jobs, got %d holding %d", operators, busiest)
	}
}

// A malformed file must not leave an agent unable to find a witness.
func TestABadRegistryFileIsSkippedNotFatal(t *testing.T) {
	dir := t.TempDir()
	pdir := filepath.Join(dir, providersDirName)
	os.MkdirAll(pdir, 0o755)
	os.WriteFile(filepath.Join(pdir, "broken.json"), []byte("{not json"), 0o644)

	r := Load(dir)
	if r.Count() == 0 {
		t.Error("a broken operator file took the shipped registry down with it")
	}
}

// Someone who does not want an operator we ship should not have to edit the
// binary to say so.
func TestALocalEntryReplacesAShippedOne(t *testing.T) {
	dir := t.TempDir()
	pdir := filepath.Join(dir, providersDirName)
	os.MkdirAll(pdir, 0o755)
	os.WriteFile(filepath.Join(pdir, "mine.json"), []byte(`{
      "version": 1,
      "providers": [{"id":"grapeid.org","operator":"someone else",
                     "endpoints":[{"capability":"relay","url":"https://mine.test"}]}]
    }`), 0o644)

	r := Load(dir)
	p, ok := r.Get("grapeid.org")
	if !ok {
		t.Fatal("entry missing after local override")
	}
	if p.Operator != "someone else" {
		t.Errorf("the local file did not win; operator is %q", p.Operator)
	}
}

// An operator commonly runs several witnesses under distinct AIDs. Collapsing
// them would hide that a witness set has fewer independent operators than
// endpoints.
//
// Uses its own document rather than the shipped one. What is being tested is
// that the registry keeps repeated endpoints for a capability; how many
// witnesses happen to ship today is a separate question, and tying the two
// together made this fail the moment the shipped list changed.
func TestSeveralEndpointsForOneCapabilityAreKept(t *testing.T) {
	r := &Registry{providers: map[string]*Provider{}}
	r.ingest("test", []byte(`{
      "version": 1,
      "providers": [{"id":"two-witnesses.example","operator":"someone",
        "endpoints":[
          {"capability":"witness","url":"https://w1.example","aid":"BAAA1"},
          {"capability":"witness","url":"https://w2.example","aid":"BAAA2"}
        ]}]
    }`))
	p, ok := r.Get("two-witnesses.example")
	if !ok {
		t.Fatal("the operator was not ingested")
	}
	witnesses := p.EndpointsFor(CapabilityWitness)
	if len(witnesses) != 2 {
		t.Fatalf("expected both witness endpoints kept, got %d", len(witnesses))
	}
	seen := map[string]bool{}
	for _, w := range witnesses {
		if seen[w.AID] {
			t.Errorf("duplicate witness AID %s would inflate a threshold without adding an observer", w.AID)
		}
		seen[w.AID] = true
	}
}

// Every witness that ships must be designatable, and designatable means named
// by the non-transferable key its receipts verify against. A witness list is
// written into an inception event and cannot be amended, so shipping one that
// could never be checked would be shipping a permanent mistake.
func TestEveryShippedWitnessCanActuallyBeDesignated(t *testing.T) {
	r := Load("")
	p, ok := r.Get("grapeid.org")
	if !ok {
		t.Skip("shipped registry not present")
	}
	witnesses := p.EndpointsFor(CapabilityWitness)
	if len(witnesses) == 0 {
		t.Fatal("no witness ships, so a new identity has nobody to be witnessed by")
	}
	for _, w := range witnesses {
		if len(w.AID) != 44 || w.AID[0] != 'B' {
			t.Errorf("witness %s is named %q, which is not a non-transferable identifier; "+
				"its receipts could not be checked without resolving a key log first",
				w.URL, w.AID)
		}
	}
	if len(p.Capabilities()) < 4 {
		t.Errorf("expected the shipped operator to offer several capabilities, got %v", p.Capabilities())
	}
}
