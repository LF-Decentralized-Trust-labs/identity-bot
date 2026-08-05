package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/store"
)

// An organisation must not end up owning itself.
//
// Redeeming a signing invite used to write an employee row saying "Super Admin"
// and file a signature beside it as evidence. Nothing consulted that before
// acting, so ownerAuthority() fell through to its default — the agent's own
// identity — and the organisation answered to nobody but itself. On rented
// hardware that means the box holds the only key that matters.
//
// The fallback is the reason this was invisible rather than broken: everything
// kept working, signed by the wrong party.

func orgServer(t *testing.T) (*CoreServer, string) {
	t.Helper()
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	t.Cleanup(func() { ds.Close() })
	// The org's own identity — what the agent would wrongly fall back to.
	if err := ds.SaveIdentity(store.IdentityState{
		AID:       "EORGITSELF",
		PublicKey: "DORGOWNKEY",
	}); err != nil {
		t.Skipf("cannot save identity: %v", err)
	}
	return &CoreServer{DataDir: dir, DataStore: ds}, dir
}

// Before anybody signs, the agent falls back to itself. That is the state the
// ceremony has to move it out of, and pinning it here is what makes the next
// test mean something.
func TestAnUnfoundedOrgAnswersToItself(t *testing.T) {
	s, _ := orgServer(t)

	oa, err := s.ownerAuthority()
	if err != nil {
		t.Fatalf("owner authority: %v", err)
	}
	if oa.AID != "EORGITSELF" {
		t.Fatalf("expected the fallback to the agent's own identity, got %q", oa.AID)
	}
}

// After sealing, the organisation answers to the signer rather than to itself.
func TestSealingMakesTheSignerTheOwner(t *testing.T) {
	s, _ := orgServer(t)

	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID:       "ESIGNERPAIRWISE",
		PublicKey: "DLQN2ahzZXKRE5jrwfdWAD3LKCJ9b1A4jlwFWGoCjiux",
	}); err != nil {
		t.Fatalf("seal: %v", err)
	}

	oa, err := s.ownerAuthority()
	if err != nil {
		t.Fatalf("owner authority: %v", err)
	}
	if oa.AID != "ESIGNERPAIRWISE" {
		t.Fatalf("the org still answers to %q — sealing did not take", oa.AID)
	}
	if oa.PublicKey == "DORGOWNKEY" {
		t.Fatal("the org is still its own owner")
	}
}

// A signer with no public key cannot be sealed, so redeeming must refuse rather
// than record an organisation whose owner cannot be checked — which is exactly
// the state being fixed.
func TestRedeemingWithoutAPublicKeyIsRefused(t *testing.T) {
	s, _ := orgServer(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/signer/invites/tok/redeem",
		strings.NewReader(`{"pairwise_aid":"ESIGNER","vouch_sig":"sig"}`))
	s.handleRedeemSignerInvite(w, r)

	if w.Code == http.StatusOK {
		t.Fatal("an organisation was founded with an owner it could not verify")
	}
	if !strings.Contains(w.Body.String(), "public_key") {
		t.Fatalf("the refusal does not name what is missing: %s", w.Body)
	}
}

// Sealing an owner whose key is malformed must fail rather than store it. A
// record that cannot be parsed later is worse than no record: ownerAuthority()
// errors on it instead of falling back, so the agent becomes unusable rather
// than merely unowned.
func TestAMalformedOwnerKeyIsNotSealed(t *testing.T) {
	s, _ := orgServer(t)

	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID:       "ESIGNER",
		PublicKey: "not a verkey",
	}); err == nil {
		t.Fatal("a malformed owner key was accepted")
	}

	// And the agent is still usable afterwards.
	if _, err := s.ownerAuthority(); err != nil {
		t.Fatalf("a refused seal left the agent broken: %v", err)
	}
}
