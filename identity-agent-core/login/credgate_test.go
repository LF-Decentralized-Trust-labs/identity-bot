package login

import "testing"

func TestPresentCredentials(t *testing.T) {
	h := &Handler{
		HeldCredentials: func() []PresentedCredential {
			return []PresentedCredential{
				{SAID: "c1", SchemaSAID: "SCHEMA_EMP", IssuerAID: "AID_ORG", Status: "issued"},
				{SAID: "c2", SchemaSAID: "SCHEMA_OTHER", IssuerAID: "AID_ORG", Status: "issued"},
				{SAID: "c3", SchemaSAID: "SCHEMA_REV", IssuerAID: "AID_ORG", Status: "revoked"},
			}
		},
	}

	// Requests the employee schema → presents exactly that credential.
	b := &ChallengeBundle{RequestedCredentials: []RequestedCredential{{SchemaSAID: "SCHEMA_EMP", Required: true}}}
	got := h.presentCredentials(b)
	if len(got) != 1 {
		t.Fatalf("expected 1 presented, got %d", len(got))
	}
	if pc, ok := got[0].(PresentedCredential); !ok || pc.SAID != "c1" {
		t.Fatalf("expected c1, got %#v", got[0])
	}

	// A revoked held credential is never presented.
	b2 := &ChallengeBundle{RequestedCredentials: []RequestedCredential{{SchemaSAID: "SCHEMA_REV"}}}
	if n := len(h.presentCredentials(b2)); n != 0 {
		t.Fatalf("revoked credential should not be presented, got %d", n)
	}

	// No requested credentials → nothing presented.
	if n := len(h.presentCredentials(&ChallengeBundle{})); n != 0 {
		t.Fatalf("no request → empty, got %d", n)
	}

	// No accessor wired → nothing presented (safe default).
	h.HeldCredentials = nil
	if n := len(h.presentCredentials(b)); n != 0 {
		t.Fatalf("nil accessor → empty, got %d", n)
	}
}

func TestIsCredentialUsable(t *testing.T) {
	for _, s := range []string{"", "issued", "valid", "active"} {
		if !isCredentialUsable(s) {
			t.Fatalf("%q should be usable", s)
		}
	}
	for _, s := range []string{"revoked", "expired", "suspended"} {
		if isCredentialUsable(s) {
			t.Fatalf("%q should NOT be usable", s)
		}
	}
}
