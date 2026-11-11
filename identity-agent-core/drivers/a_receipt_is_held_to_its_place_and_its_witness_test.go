package drivers

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"identity-agent-core/iacrypto"

	keri "github.com/grapeid/keri-go"
)

func witnessKey(t *testing.T) (aid string, seed []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return iacrypto.NonTransferableAIDQB64(pub), priv.Seed()
}

// The index is a place in the witness list and sits outside what the witness
// signed, so the same signature carries any index. VerifyEventReceipt holds it
// to the list it is given, with no keripy vector involved.
func TestAReceiptIsIndexedAtItsWitnessesPlaceInTheList(t *testing.T) {
	a, aSeed := witnessKey(t)
	b, _ := witnessKey(t)
	event := []byte(`{"v":"KERI10JSON000000_","t":"icp","d":"Eevent","i":"Eevent","s":"0"}`)
	list := []string{b, a} // a stands at 1

	right, err := SignEventReceipt(event, aSeed, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEventReceipt(a, event, "Eevent", right, list); err != nil {
		t.Fatalf("a receipt at its place was refused: %v", err)
	}
	wrong, _ := SignEventReceipt(event, aSeed, 0)
	if VerifyEventReceipt(a, event, "Eevent", wrong, list) == nil {
		t.Fatal("a receipt indexed at another witness's place was accepted")
	}
	// A witness the list does not hold has no place at all.
	if VerifyEventReceipt(a, event, "Eevent", right, []string{b, b}) == nil {
		t.Fatal("a receipt from a witness outside the list was accepted")
	}
	// No list given: the place is checked where the list is known.
	if err := VerifyEventReceipt(a, event, "Eevent", wrong, nil); err != nil {
		t.Fatalf("with no list the signature alone is checked: %v", err)
	}
}

// A witness is named by its own key. A transferable identifier names a key
// that can change, so a signature under one is not a receipt, even when the
// signature is a good one.
func TestAReceiptFromANameThatIsNotAKeyIsRefused(t *testing.T) {
	_, seed := witnessKey(t)
	event := []byte(`{"v":"KERI10JSON000000_","t":"icp","d":"Eevent","i":"Eevent","s":"0"}`)
	sig, _ := SignEventReceipt(event, seed, 0)
	// A transferable key, which a good signature under verifies as a signature:
	// it is still not a witness's name.
	signer, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	tpub, _ := signer.PublicKey()
	raw, _ := signer.Sign(event)
	tsig, _ := iacrypto.MatterIndexedSigQB64("A", 0, raw, 88)
	if VerifyEventReceipt(tpub, event, "Eevent", tsig, nil) == nil {
		t.Fatal("a signature under a transferable key was accepted as a witness's receipt")
	}
	for _, name := range []string{"EDigestNotAKey0123456789ABCDEFGHIJKLMNOPQRS", "not an identifier"} {
		if VerifyEventReceipt(name, event, "Eevent", sig, nil) == nil {
			t.Fatalf("%q was accepted as a witness", name)
		}
		if CheckReceiptShape(name, sig) == nil {
			t.Fatalf("%q passed the shape check", name)
		}
	}
}

// The count a key log reports takes in only receipts at their witness's place
// in the list in force: a genuine signature carrying another index is not one.
func TestTheCountOfWitnessesLeavesOutAReceiptAtTheWrongIndex(t *testing.T) {
	v, raw := loadVector(t)
	r := v.Receipts[0]
	seed, _ := base64.StdEncoding.DecodeString(r.SeedB64)
	count := func(index int) int {
		sig, err := SignEventReceipt(raw, seed, index)
		if err != nil {
			t.Fatal(err)
		}
		rows, _ := witnessingReport(ValidateKELInput{
			RawEvents: [][]byte{raw},
			Receipts:  map[string][]WitnessReceipt{v.EventSAID: {{WitnessAID: r.Witness, CesrSignature: sig}}},
		})
		return rows[0].Verified
	}
	if got := count(r.Index); got != 1 {
		t.Fatalf("the receipt at its place counted %d", got)
	}
	if got := count(1 - r.Index); got != 0 {
		t.Fatalf("the same signature at another index counted %d", got)
	}
}

// The event an entry is, is what its bytes say: a "d" or "t" served beside the
// bytes is not read.
func TestEventIDOfRecordIgnoresATopLevelDAndT(t *testing.T) {
	raw := base64.StdEncoding.EncodeToString([]byte(`{"t":"icp","d":"Ereal","i":"Eaid","s":"0"}`))
	said, ilk := EventIDOfRecord(map[string]interface{}{"raw_bytes_b64": raw, "d": "Eforged", "t": "rot"})
	if said != "Ereal" || ilk != "icp" {
		t.Fatalf("read %q %q from beside the bytes", said, ilk)
	}
	if said, ilk := EventIDOfRecord(map[string]interface{}{"d": "Eforged", "t": "rot"}); said != "" || ilk != "" {
		t.Fatalf("a record with no bytes gave %q %q", said, ilk)
	}
}
