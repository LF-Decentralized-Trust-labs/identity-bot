package server

import (
	"strings"
	"testing"
)

// The attack this prevents: an originator serves one Ask when the user is
// deciding, and a different one when the agent executes. Both are validly
// signed by the same minter, so signature verification passes on each.
func TestBindConsentRefusesSubstitutedAsk(t *testing.T) {
	approved := []byte(`{"t":3,"org_name":"Acme","role":"Intern"}`)
	substituted := []byte(`{"t":3,"org_name":"Acme","role":"Admin","requested_credentials":["*"]}`)

	digestOfApproved := askDigest(approved)

	if err := bindConsent(digestOfApproved, approved); err != nil {
		t.Fatalf("the approved Ask must execute: %v", err)
	}

	err := bindConsent(digestOfApproved, substituted)
	if err == nil {
		t.Fatal("a substituted Ask executed — the user approved Intern and Admin ran")
	}
	if !strings.Contains(err.Error(), "differs from the one you approved") {
		t.Errorf("the error must tell the user what happened, got: %v", err)
	}
}

// Absent digest is refused rather than waved through, so a client that has not
// been updated fails loudly instead of silently losing the protection.
func TestBindConsentRequiresDigest(t *testing.T) {
	err := bindConsent("", []byte(`{"t":1}`))
	if err == nil {
		t.Fatal("a missing ask_digest was accepted — consent would be unbound")
	}
	if !strings.Contains(err.Error(), "ask_digest is required") {
		t.Errorf("the error must say what the client should send, got: %v", err)
	}
}

// A one-byte change must not slip through.
func TestBindConsentDetectsSingleByteChange(t *testing.T) {
	a := []byte(`{"t":3,"role":"Intern"}`)
	b := []byte(`{"t":3,"role":"Intern "}`)
	if bindConsent(askDigest(a), b) == nil {
		t.Fatal("a one-byte difference was accepted")
	}
}

// The digest must be stable — a preview and a later execute of identical bytes
// must agree, or every legitimate approval would be refused.
func TestAskDigestIsStable(t *testing.T) {
	b := []byte(`{"t":2,"display_name":"Rob"}`)
	if askDigest(b) != askDigest(b) {
		t.Fatal("askDigest is not deterministic")
	}
	if askDigest(b) == askDigest([]byte(`{"t":2,"display_name":"Bob"}`)) {
		t.Fatal("different Asks produced the same digest")
	}
}
