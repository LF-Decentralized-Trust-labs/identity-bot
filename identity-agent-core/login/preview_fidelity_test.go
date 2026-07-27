package login

import "testing"

// A site can ask for credentials and a trust score as well as profile fields.
// The preview has to carry them, or the consent screen describes a smaller
// request than the one being approved.
func TestPreviewCarriesRequestedCredentials(t *testing.T) {
	h := &Handler{HeldCredentials: func() []PresentedCredential {
		return []PresentedCredential{
			{SchemaSAID: "SCHEMA_EMP", Status: "issued"},
			{SchemaSAID: "SCHEMA_REVOKED", Status: "revoked"},
		}
	}}
	bundle := &ChallengeBundle{RequestedCredentials: []RequestedCredential{
		{SchemaSAID: "SCHEMA_EMP", Required: true},
		{SchemaSAID: "SCHEMA_REVOKED", Required: true},
		{SchemaSAID: "SCHEMA_NOT_HELD"},
	}}

	got := h.previewRequestedCredentials(bundle)
	if len(got) != 3 {
		t.Fatalf("expected all 3 requests previewed, got %d", len(got))
	}
	if !got[0].Held {
		t.Error("a usable held credential should preview as held")
	}
	// The preview must make the same match presentCredentials makes, or it
	// promises something approving will not deliver.
	if got[1].Held {
		t.Error("a revoked credential is never presented and must not preview as held")
	}
	if got[2].Held {
		t.Error("a credential we do not hold must not preview as held")
	}
	if !got[0].Required || got[2].Required {
		t.Error("required flags did not survive into the preview")
	}
}

// No credential store wired (mobile, or an agent without one) must not claim we
// hold anything.
func TestPreviewWithoutCredentialStoreHoldsNothing(t *testing.T) {
	h := &Handler{}
	got := h.previewRequestedCredentials(&ChallengeBundle{
		RequestedCredentials: []RequestedCredential{{SchemaSAID: "SCHEMA_EMP", Required: true}},
	})
	if len(got) != 1 || got[0].Held {
		t.Fatalf("expected the request previewed as not held, got %+v", got)
	}
}

func TestPreviewOmitsCredentialsWhenNoneRequested(t *testing.T) {
	h := &Handler{}
	if got := h.previewRequestedCredentials(&ChallengeBundle{}); got != nil {
		t.Errorf("expected no credential rows, got %+v", got)
	}
}
