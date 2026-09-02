package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"
)

// A founding nobody signed is not something anybody can act on.
//
// The signature is over bytes the engine produces and is made by the device
// holding the recovery phrase, so there is nothing to sign until the event
// exists. That window was never closed: the signature was computed and read by
// nobody, and every identity founded through the application published a key
// history in which nothing had been authorised. A counterparty checking
// properly refuses such a log, so the identity works alone and can convince
// nobody — and nothing said so.
func aFoundedIdentityWithNoSignature(t *testing.T) (*CoreServer, ed25519.PrivateKey, []byte, string) {
	t.Helper()
	s := agentWithNoIdentity(t)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	aid := iacrypto.NonTransferableAIDQB64(pub)
	key := iacrypto.VerkeyQB64(pub)
	// Stands in for what the engine serialised. What matters is that a
	// signature is checked against exactly these bytes.
	raw := []byte(`{"v":"KERI10JSON000000_","t":"icp","i":"` + aid + `"}`)

	if err := s.DataStore.SaveIdentity(store.IdentityState{
		AID: aid, PublicKey: key, EventCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.DataStore.SaveEvent(store.EventRecord{
		AID: aid, SequenceNumber: 0, EventType: "icp",
		PublicKey:   key,
		RawBytesB64: base64.StdEncoding.EncodeToString(raw),
	}); err != nil {
		t.Fatal(err)
	}
	return s, priv, raw, aid
}

func attach(t *testing.T, s *CoreServer, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/inception/signature",
		strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	s.handleAttachInceptionSignature(rec, req)
	return rec
}

func TestTheSignatureOverAFoundingIsAttachedAndChecked(t *testing.T) {
	s, priv, raw, aid := aFoundedIdentityWithNoSignature(t)

	if !s.theFoundingEventIsUnsigned() {
		t.Fatal("precondition: the founding should start unsigned")
	}

	sig, err := login.SignString(string(raw), priv.Seed())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"aid": aid, "cesr_signature": sig})
	if rec := attach(t, s, string(body)); rec.Code != http.StatusOK {
		t.Fatalf("a genuine signature was refused: %d %s", rec.Code, rec.Body.String())
	}

	if s.theFoundingEventIsUnsigned() {
		t.Fatal("the signature was accepted and not recorded, so the key history " +
			"this identity publishes is still one nobody can verify")
	}
}

// A route that wrote whatever it was handed would be worse than the gap it
// closes: an unsigned history is refused by everybody, and a wrongly signed one
// is refused by everybody while looking right to its owner.
func TestASignatureNobodyMadeOverThisEventIsRefused(t *testing.T) {
	s, _, raw, aid := aFoundedIdentityWithNoSignature(t)

	somebodyElse, _, _ := ed25519.GenerateKey(nil)
	_ = somebodyElse
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	theirs, err := login.SignString(string(raw), otherPriv.Seed())
	if err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]string{"aid": aid, "cesr_signature": theirs})
	if rec := attach(t, s, string(body)); rec.Code != http.StatusBadRequest {
		t.Fatalf("a signature by somebody else was accepted: %d %s",
			rec.Code, rec.Body.String())
	}
	if !s.theFoundingEventIsUnsigned() {
		t.Fatal("a refused signature was written anyway")
	}
}

// And one made over different bytes, by the right key.
func TestASignatureOverSomethingElseIsRefused(t *testing.T) {
	s, priv, _, aid := aFoundedIdentityWithNoSignature(t)

	wrong, err := login.SignString("some other bytes entirely", priv.Seed())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"aid": aid, "cesr_signature": wrong})
	if rec := attach(t, s, string(body)); rec.Code != http.StatusBadRequest {
		t.Fatalf("a signature over other bytes was accepted: %d %s",
			rec.Code, rec.Body.String())
	}
}

// A signature is attached to THIS agent's own founding and nothing else.
func TestASignatureForADifferentIdentityIsRefused(t *testing.T) {
	s, priv, raw, _ := aFoundedIdentityWithNoSignature(t)

	sig, err := login.SignString(string(raw), priv.Seed())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{
		"aid": "ESOMEBODYELSE", "cesr_signature": sig})
	if rec := attach(t, s, string(body)); rec.Code != http.StatusForbidden {
		t.Fatalf("a signature was attached to a different identity: %d %s",
			rec.Code, rec.Body.String())
	}
}
