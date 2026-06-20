package login

import (
	"strings"
	"testing"
)

// Tier-1 headless test (no server): proves the privacy + disclosure contract of
// "Sign in with Identity Agent" using the in-process login engine.
//
//	- the RP receives a PAIRWISE AID, never a Root AID (the login contract)
//	- the pairwise AID is stable per site, and unlinkable across sites
//	- the signed Grant carries that pairwise AID as `i`
//	- only the fields the site requested are disclosed
//	- the relationship OOBI keeps the RP-hosted path (regression guard for the
//	  relayBaseFromOOBI / approve-time 401 fix)
func TestLoginPairwiseAndDisclosures(t *testing.T) {
	store, err := NewRelationshipStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Store: store, DevRelay: "http://127.0.0.1:8765"}

	bundleA := &ChallengeBundle{
		V: "ASK1", T: 1, SiteAID: "EsiteAAA",
		SiteOOBI:             "https://a.example/auth/ia/site/oobi/EsiteAAA",
		Audience:             "https://a.example",
		Nonce:                "nonceA",
		RequestedDisclosures: []string{"display_name", "email"},
	}
	bundleB := &ChallengeBundle{
		V: "ASK1", T: 1, SiteAID: "EsiteBBB",
		SiteOOBI:             "https://b.example/auth/ia/site/oobi/EsiteBBB",
		Audience:             "https://b.example",
		Nonce:                "nonceB",
		RequestedDisclosures: []string{"display_name"},
	}

	relA, err := h.getOrCreateRelationship("EsiteAAA", bundleA)
	if err != nil {
		t.Fatal(err)
	}
	relA2, err := h.getOrCreateRelationship("EsiteAAA", bundleA)
	if err != nil {
		t.Fatal(err)
	}
	relB, err := h.getOrCreateRelationship("EsiteBBB", bundleB)
	if err != nil {
		t.Fatal(err)
	}

	// Pairwise AID present and well-formed (E-prefixed), never empty/root.
	if len(relA.PairwiseAID) == 0 || relA.PairwiseAID[0] != 'E' {
		t.Fatalf("expected E-prefixed pairwise AID, got %q", relA.PairwiseAID)
	}
	// Stable per site.
	if relA.PairwiseAID != relA2.PairwiseAID {
		t.Fatalf("pairwise AID not stable per site: %q vs %q", relA.PairwiseAID, relA2.PairwiseAID)
	}
	// Unlinkable across sites — different sites MUST get different pairwise AIDs.
	if relA.PairwiseAID == relB.PairwiseAID {
		t.Fatalf("pairwise AIDs collide across sites (correlation leak): %q", relA.PairwiseAID)
	}
	// Relationship OOBI keeps the RP-hosted path prefix (the 401 regression guard).
	if !strings.Contains(relA.RelayOOBI, "/auth/ia/site/oobi/") {
		t.Fatalf("relationship OOBI dropped the RP-hosted path: %q", relA.RelayOOBI)
	}

	// The signed Grant carries the pairwise AID as `i` and only requested fields.
	asrt, err := h.buildAssertion(relA, bundleA, nil)
	if err != nil {
		t.Fatal(err)
	}
	if asrt.I != relA.PairwiseAID {
		t.Fatalf("assertion i=%q, want pairwise AID %q", asrt.I, relA.PairwiseAID)
	}
	if asrt.Audience != bundleA.Audience || asrt.Nonce != bundleA.Nonce {
		t.Fatalf("assertion not bound to the Ask audience/nonce")
	}
	if len(asrt.Disclosures) != 2 {
		t.Fatalf("expected exactly the 2 requested disclosures, got %d: %v", len(asrt.Disclosures), asrt.Disclosures)
	}
	if _, ok := asrt.Disclosures["display_name"]; !ok {
		t.Fatal("missing requested disclosure display_name")
	}
	if _, ok := asrt.Disclosures["email"]; !ok {
		t.Fatal("missing requested disclosure email")
	}
	if asrt.Sig == "" {
		t.Fatal("assertion not signed")
	}
}
