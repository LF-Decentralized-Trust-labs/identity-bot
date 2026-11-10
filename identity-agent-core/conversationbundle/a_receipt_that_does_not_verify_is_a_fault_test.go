package conversationbundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
)

// A witness receipt in a bundle is checked against the event it sits on. One
// that does not verify is a changed receipt, and the bundle says so; one that
// does is not a fault.
func TestAReceiptInABundleThatDoesNotVerifyIsAFault(t *testing.T) {
	_, b := theVector(t)
	if len(b.KeyLogs) == 0 || len(b.KeyLogs[0].Events) == 0 {
		t.Fatal("the vector carries no key log")
	}
	rawEvent, err := base64.StdEncoding.DecodeString(b.KeyLogs[0].Events[0].Raw)
	if err != nil {
		t.Skipf("the event is not plain base64 here: %v", err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	witness := iacrypto.NonTransferableAIDQB64(pub)
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	good, _ := drivers.SignEventReceipt(rawEvent, priv.Seed(), 0)
	forged, _ := drivers.SignEventReceipt(rawEvent, stranger.Seed(), 0)

	with := func(sig string) string {
		c := copyOf(t, b)
		c.KeyLogs[0].Events[0].Receipts = append(c.KeyLogs[0].Events[0].Receipts, Receipt{Witness: witness, Signature: sig})
		return faultsOf(VerifyAgainst(c, c.Root))
	}
	if f := with(forged); !strings.Contains(f, "does not verify") {
		t.Fatalf("a receipt another key signed was not a fault:\n%s", f)
	}
	if f := with(good); strings.Contains(f, "does not verify") {
		t.Fatalf("a genuine receipt was a fault:\n%s", f)
	}
}

// A receipt carries its witness's place in the list in force at its event,
// outside what the witness signed. In a bundle that list is the one the key log
// defines, so a copy of a genuine receipt with another index is a changed
// receipt, and the bundle says so.
func TestAReceiptAtAnotherPlaceThanItsWitnessesIsAFault(t *testing.T) {
	_, b := theVector(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	witness := iacrypto.NonTransferableAIDQB64(pub)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	other := iacrypto.NonTransferableAIDQB64(otherPub)
	// An inception that names two witnesses, with the witness at place 1. The
	// bundle will not verify as a whole with its bytes changed; the receipt is
	// judged on its own.
	raw := []byte(`{"v":"KERI10JSON000000_","t":"icp","d":"Enamed","i":"Enamed","s":"0","kt":"1","k":[],"nt":"1","n":[],"bt":"1","b":["` + other + `","` + witness + `"],"c":[],"a":[]}`)
	atPlace := func(index int) string {
		sig, _ := drivers.SignEventReceipt(raw, priv.Seed(), index)
		c := copyOf(t, b)
		c.KeyLogs[0].Events[0].Raw = base64.StdEncoding.EncodeToString(raw)
		c.KeyLogs[0].Events[0].Receipts = []Receipt{{Witness: witness, Signature: sig}}
		return faultsOf(VerifyAgainst(c, c.Root))
	}
	if f := atPlace(0); !strings.Contains(f, "a witness receipt for event 0 does not verify") {
		t.Fatalf("a receipt at the other witness's place was not a fault:\n%s", f)
	}
	if f := atPlace(1); strings.Contains(f, "a witness receipt for event 0 does not verify") {
		t.Fatalf("a receipt at its own place was a fault:\n%s", f)
	}
}
