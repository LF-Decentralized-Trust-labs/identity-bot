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

// Where a key log cannot be read as far as an event, the list of witnesses in
// force there is not known and a receipt's index is not held to it: the bundle
// is faulted for the log, not for a receipt judged against a list nobody could
// read. The same receipt at the same place is a changed one once the log reads.
func TestAReceiptIsHeldToAListOnlyWhereTheLogCanBeRead(t *testing.T) {
	_, b := theVector(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	witness := iacrypto.NonTransferableAIDQB64(pub)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	other := iacrypto.NonTransferableAIDQB64(otherPub)
	withThreshold := `{"v":"KERI10JSON000000_","t":"icp","d":"Enamed","i":"Enamed","s":"0","kt":"1","k":[],"nt":"1","n":[],"bt":"1","b":["` + other + `","` + witness + `"],"c":[],"a":[]}`
	noThreshold := strings.Replace(withThreshold, `"bt":"1",`, "", 1)

	// The receipt is at place 0, where the list has the witness at place 1.
	faultFor := func(event string) string {
		raw := []byte(event)
		sig, _ := drivers.SignEventReceipt(raw, priv.Seed(), 0)
		c := copyOf(t, b)
		c.KeyLogs[0].Events[0].Raw = base64.StdEncoding.EncodeToString(raw)
		c.KeyLogs[0].Events[0].Receipts = []Receipt{{Witness: witness, Signature: sig}}
		return faultsOf(VerifyAgainst(c, c.Root))
	}
	const fault = "a witness receipt for event 0 does not verify"
	if f := faultFor(withThreshold); !strings.Contains(f, fault) {
		t.Fatalf("the test's receipt is meant to be at the wrong place in a log that reads:\n%s", f)
	}
	if f := faultFor(noThreshold); strings.Contains(f, fault) {
		t.Fatalf("a receipt was held to a witness list the log could not be read to give:\n%s", f)
	}
}
