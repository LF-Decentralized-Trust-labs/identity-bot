package login

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
)

// TestAskSignRoundTrip proves the generic base-layer Ask signing: signing the canonical body
// with a pairwise seed yields a sig that verifies against the pairwise pubkey, survives the sig
// being injected into the Ask (CanonicalAskBody excludes "sig"), and fails on tamper.
func TestAskSignRoundTrip(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	ask := []byte(`{"v":"ASK1","t":2,"asker_aid":"EBob","asker_oobi":"https://x/oobi/EBob","signer_oobi":"https://x/oobi/EBob","asker_alias":"Bob"}`)
	sig, err := SignAsk(ask, seed)
	if err != nil {
		t.Fatalf("SignAsk: %v", err)
	}

	// Inject the sig (as the create path does) and verify — CanonicalAskBody drops "sig".
	var m map[string]interface{}
	_ = json.Unmarshal(ask, &m)
	m["sig"] = sig
	signed, _ := json.Marshal(m)
	if ok, err := VerifyAsk(signed, sig, pub); err != nil || !ok {
		t.Fatalf("VerifyAsk on signed Ask failed: ok=%v err=%v", ok, err)
	}

	// Tamper the alias → must not verify.
	m["asker_alias"] = "Eve"
	tampered, _ := json.Marshal(m)
	if ok, _ := VerifyAsk(tampered, sig, pub); ok {
		t.Fatal("tampered Ask verified — must fail")
	}
}
