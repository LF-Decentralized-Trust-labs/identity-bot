package keymath

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
)

// A receipt signed over the event carries its witness's place in the witness
// list in force at the event, outside what the witness signed. The device
// checks receipts through verify_receipt, so a list given there holds the
// index to that place: a copy of a genuine receipt carrying another index is
// not one.
func TestAReceiptIsHeldToItsWitnesssPlaceInTheListGiven(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	witness := iacrypto.NonTransferableAIDQB64(pub)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	other := iacrypto.NonTransferableAIDQB64(otherPub)
	event := []byte(`{"v":"KERI10JSON000000_","t":"icp","d":"Eevent","i":"Eevent","s":"0"}`)
	eventB64 := base64.StdEncoding.EncodeToString(event)
	list := []string{other, witness} // the witness stands at place 1

	check := func(index int, designated []string) error {
		sig, err := drivers.SignEventReceipt(event, priv.Seed(), index)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := json.Marshal(map[string]interface{}{
			"witness": witness, "digest": "Eevent", "sig": sig, "event_b64": eventB64, "designated": designated,
		})
		_, err = Do("verify_receipt", req)
		return err
	}
	if err := check(1, list); err != nil {
		t.Fatalf("a receipt at its place in the list was refused: %v", err)
	}
	if err := check(0, list); err == nil {
		t.Fatal("a receipt at another witness's place was accepted")
	}
	// Without a list the index is not checked, as before.
	if err := check(0, nil); err != nil {
		t.Fatalf("a receipt with no list to check against was refused: %v", err)
	}
	// And the same through the function the device's operation calls.
	sig, _ := drivers.SignEventReceipt(event, priv.Seed(), 0)
	if err := VerifyEventReceipt(witness, eventB64, "Eevent", sig, list); err == nil {
		t.Fatal("VerifyEventReceipt took a mis-indexed receipt")
	}
}
