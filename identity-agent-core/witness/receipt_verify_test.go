package witness

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
)

// A witness's reply, made the way a real witness makes one.
func witnessReply(t *testing.T, said string, seedByte byte) (resp map[string]interface{}, aid string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i) + seedByte
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	aid = iacrypto.NonTransferableAIDQB64(pub)
	sig, err := login.SignString(said, seed)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]interface{}{"witness_aid": aid, "cesr_signature": sig}, aid
}

const testSAID = "EEventSAID0123456789ABCDEFGHIJKLMNOPQRSTUVW"

// The reply has to be read. Counting a receipt because the POST returned 2xx
// means a witness that signed nothing, signed something else, or is not the
// witness we addressed all count the same as one that witnessed properly.
func TestAGenuineReceiptIsAccepted(t *testing.T) {
	resp, aid := witnessReply(t, testSAID, 1)
	sig, got, err := receiptFromResponse(resp, testSAID)
	if err != nil {
		t.Fatalf("a genuine receipt was rejected: %v", err)
	}
	if got != aid || sig == "" {
		t.Fatalf("witness %q sig %q", got, sig)
	}
}

func TestAReplyWithNoReceiptIsNotCounted(t *testing.T) {
	for _, resp := range []map[string]interface{}{
		nil,
		{},
		{"status": "accepted"},
		{"witness_aid": "BSomeWitness"},
	} {
		if _, _, err := receiptFromResponse(resp, testSAID); err == nil {
			t.Fatalf("a reply carrying no receipt was counted: %v", resp)
		}
	}
}

// The signature must cover THIS event. A receipt for another event is a real
// signature by a real witness and still says nothing about this one.
func TestAReceiptForAnotherEventIsRefused(t *testing.T) {
	resp, _ := witnessReply(t, "EDifferentEvent6789ABCDEFGHIJKLMNOPQRSTUVWX", 1)
	if _, _, err := receiptFromResponse(resp, testSAID); err == nil {
		t.Fatal("a receipt issued for a different event was accepted")
	}
}

// A witness that cannot be checked from its own name is no use: the point of a
// non-transferable identifier is that the verifier needs nothing else.
func TestAWitnessNotNamedByAKeyIsRefused(t *testing.T) {
	resp, _ := witnessReply(t, testSAID, 1)
	resp["witness_aid"] = "EvRHjssG5WJjwq5c2AA8yOfY7VT3keG0XOtdRLz195P8" // the old, unparseable shape
	_, _, err := receiptFromResponse(resp, testSAID)
	if err == nil {
		t.Fatal("a witness whose name is not a key was accepted")
	}
	if !strings.Contains(err.Error(), "check against") {
		t.Errorf("the reason should say the name is not checkable, got: %v", err)
	}
}

// Someone else's genuine signature, offered under the designated witness's
// name, must not pass.
func TestASignatureFromAnotherKeyIsRefused(t *testing.T) {
	impostor, _ := witnessReply(t, testSAID, 9)
	_, designated := witnessReply(t, testSAID, 1)
	impostor["witness_aid"] = designated
	if _, _, err := receiptFromResponse(impostor, testSAID); err == nil {
		t.Fatal("a signature by a different key passed under the designated witness's name")
	}
}
