package server

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/store"
)

// The chain this closes: anyone could POST an acceptance naming any identity,
// a waiting contact moved to "accepted", and "accepted" is the status that
// authorises fetching that identity's encryption keys and registering them as
// somebody to encrypt to. Unauthenticated POST to registered peer, in one step.
func TestAnUnsignedAcceptanceCannotMoveAContact(t *testing.T) {
	s := newExchangeTestServer(t)
	if err := s.DataStore.SaveContact(store.ContactRecord{
		AID: "ETHEIRS", Alias: "them", Status: "pending_outbound",
		PublicKey: "DGwUXQpxNXKlbEwLLL0zAFTMlWlBEyAKWpEfLGxWEIYd",
	}); err != nil {
		t.Fatal(err)
	}

	rec := postExchange(t, s, map[string]interface{}{
		"type": "acceptance", "sender_aid": "ETHEIRS",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("an unsigned acceptance returned %d, want 403", rec.Code)
	}

	after, _ := s.DataStore.GetContact("ETHEIRS")
	if after.Status != "pending_outbound" {
		t.Fatalf("the contact moved to %q on an unsigned acceptance", after.Status)
	}
}

// A signature that does not verify against the key we already hold is the same
// refusal — otherwise anyone could sign with their own key and be believed.
func TestAnAcceptanceSignedByTheWrongKeyIsRefused(t *testing.T) {
	s := newExchangeTestServer(t)
	_ = s.DataStore.SaveContact(store.ContactRecord{
		AID: "ETHEIRS", Status: "pending_outbound",
		PublicKey: "DGwUXQpxNXKlbEwLLL0zAFTMlWlBEyAKWpEfLGxWEIYd",
	})

	rec := postExchange(t, s, map[string]interface{}{
		"type": "acceptance", "sender_aid": "ETHEIRS",
		"sig": "0BCdGVzdC1zaWduYXR1cmUtdGhhdC1kb2VzLW5vdC12ZXJpZnktYXQtYWxsLW5vcGU",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a bogus signature returned %d, want 403", rec.Code)
	}
	after, _ := s.DataStore.GetContact("ETHEIRS")
	if after.Status == "accepted" {
		t.Fatal("a bogus signature moved the contact")
	}
}

// An acceptance for somebody this agent has never heard of has no key to be
// checked against, so it cannot be believed either.
func TestAnAcceptanceFromAStrangerIsRefused(t *testing.T) {
	s := newExchangeTestServer(t)
	rec := postExchange(t, s, map[string]interface{}{
		"type": "acceptance", "sender_aid": "ENOBODY-WE-KNOW", "sig": "0BAAAA",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("returned %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "no record") {
		t.Errorf("the reason is unclear: %s", rec.Body.String())
	}
}

// An introduction from an identity we already know is checked against the key
// we recorded, before any status moves. That branch used to upgrade a contact
// to accepted on nothing but a claimed identifier.
func TestAnUnsignedIntroductionFromAKnownContactIsRefused(t *testing.T) {
	s := newExchangeTestServer(t)
	_ = s.DataStore.SaveContact(store.ContactRecord{
		AID: "ETHEIRS", Status: "verified",
		PublicKey: "DGwUXQpxNXKlbEwLLL0zAFTMlWlBEyAKWpEfLGxWEIYd",
	})

	rec := postExchange(t, s, map[string]interface{}{
		"type": "introduction", "sender_aid": "ETHEIRS",
		"sender_oobi": "https://example.invalid/oobi",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("an unsigned introduction returned %d, want 403", rec.Code)
	}
	after, _ := s.DataStore.GetContact("ETHEIRS")
	if after.Status == "accepted" {
		t.Fatal("an unsigned introduction upgraded a contact to accepted")
	}
}

// What this agent sends must be signed, or every counterparty will rightly
// refuse it and contact exchange stops working entirely.
func TestWhatWeSendIsSigned(t *testing.T) {
	s := newExchangeTestServer(t)
	payload := map[string]interface{}{"type": "acceptance", "sender_aid": "EOURS"}
	sig, err := s.signExchange(payload)
	if err != nil {
		t.Fatalf("this agent could not sign as itself: %v", err)
	}
	if sig == "" {
		t.Fatal("no signature was produced")
	}
	payload["sig"] = sig

	raw, _ := json.Marshal(payload)
	id, _ := s.DataStore.GetIdentity()
	if err := verifyExchangeSignature(raw, sig, id.PublicKey); err != nil {
		t.Fatalf("what we sign does not verify against the key we publish: %v", err)
	}
	// And the signature must not verify once the body has been altered.
	tampered := map[string]interface{}{"type": "acceptance", "sender_aid": "ESOMEBODY-ELSE", "sig": sig}
	traw, _ := json.Marshal(tampered)
	if err := verifyExchangeSignature(traw, sig, id.PublicKey); err == nil {
		t.Error("the signature still verified after the sender was changed")
	}
}

func postExchange(t *testing.T, s *CoreServer, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	s.handleExchange(rec, httptest.NewRequest(http.MethodPost, "/api/exchange", strings.NewReader(string(raw))))
	return rec
}

// An agent with an identity whose key is derivable from its own root seed —
// which is what signing an exchange requires.
func newExchangeTestServer(t *testing.T) *CoreServer {
	t.Helper()
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	s := &CoreServer{DataDir: dir, DataStore: ds, EventHub: NewEventHub()}

	rootSeed, err := ensureRootSeed(dir)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := backup.DerivePairwiseSeed(rootSeed, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if err := ds.SaveIdentity(store.IdentityState{
		AID:             "EOURS",
		PublicKey:       iacrypto.VerkeyQB64(pub),
		DerivationIndex: 0,
		KeyGeneration:   0,
	}); err != nil {
		t.Fatal(err)
	}
	return s
}
