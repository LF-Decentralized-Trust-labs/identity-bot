package witnessproto

import (
	"crypto/ed25519"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// A witness is named by its own key, so a receipt is checked with nothing
// fetched. A transferable identifier names a key that can be rotated away, and
// a name that is not a key names nothing, so a receipt from either is refused
// even when its signature is good under the key the name carries.
//
// Fails when VerifyEventReceipt accepts a witness that is not a canonical
// non-transferable identifier.
func TestAReceiptFromAWitnessNotNamedByItsKeyIsRefused(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	transferable, err := keri.NewSoftwareSigner(seed, true)
	if err != nil {
		t.Fatal(err)
	}
	dAID, err := transferable.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if dAID[0] != 'D' {
		t.Fatalf("expected a transferable identifier, got %q", dAID)
	}
	event := []byte(`{"v":"KERI10JSON000000_","t":"icp","d":"Eevent","i":"Econtroller","s":"0"}`)
	said := "Eevent"

	indexed, err := SignEventReceipt(event, seed, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEventReceipt(dAID, event, said, indexed, nil); err == nil {
		t.Fatal("a receipt over the event from a transferable identifier was accepted")
	}

	earlier, err := keri.MatterQB64(keri.CodeEd25519Sig, ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(said)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEventReceipt(dAID, nil, said, earlier, nil); err == nil {
		t.Fatal("an earlier-form receipt from a transferable identifier was accepted")
	}

	for _, name := range []string{"not a witness", "B", ""} {
		if err := VerifyEventReceipt(name, event, said, indexed, nil); err == nil {
			t.Fatalf("a receipt from %q was accepted", name)
		}
	}

	// Control: the same key as a non-transferable witness is accepted.
	witness, err := keri.NewSoftwareSigner(seed, false)
	if err != nil {
		t.Fatal(err)
	}
	bAID, err := witness.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEventReceipt(bAID, event, said, indexed, nil); err != nil {
		t.Fatalf("the witness's own receipt was refused: %v", err)
	}
}
