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
