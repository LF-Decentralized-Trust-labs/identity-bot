package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
)

// A receipt signed over the event is kept only with the event, and checked
// against it; and one that does not verify never replaces a verified one that
// is held, in either store.
func TestAVerifiedReceiptIsNeverReplacedByOneThatIsNot(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	witness := iacrypto.NonTransferableAIDQB64(pub)
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	event := []byte(`{"v":"KERI10JSON000000_","t":"icp","d":"Eevent","i":"Eevent","s":"0"}`)
	const said = "Eevent"
	good, _ := drivers.SignEventReceipt(event, priv.Seed(), 0)
	forged, _ := drivers.SignEventReceipt(event, stranger.Seed(), 0)

	sqlite, err := NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	type receipts interface {
		SaveWitnessReceipt(WitnessReceiptRecord) error
		GetWitnessReceipts(string) ([]WitnessReceiptRecord, error)
	}
	for name, st := range map[string]receipts{"sqlite": sqlite, "file": file} {
		t.Run(name, func(t *testing.T) {
			// The branch that wants the event.
			err := st.SaveWitnessReceipt(WitnessReceiptRecord{EventSAID: said, WitnessAID: witness, CesrSignature: good})
			if !errors.Is(err, ErrReceiptDoesNotVerify) {
				t.Fatalf("a receipt over the event was kept without the event: %v", err)
			}
			if held, _ := st.GetWitnessReceipts(said); len(held) != 0 {
				t.Fatalf("kept: %+v", held)
			}
			// The branch that checks it against the event.
			err = st.SaveWitnessReceipt(WitnessReceiptRecord{EventSAID: said, WitnessAID: witness, CesrSignature: forged, Event: event})
			if !errors.Is(err, ErrReceiptDoesNotVerify) {
				t.Fatalf("a receipt another key signed was kept: %v", err)
			}
			if err := st.SaveWitnessReceipt(WitnessReceiptRecord{EventSAID: said, WitnessAID: witness, CesrSignature: good, Event: event}); err != nil {
				t.Fatal(err)
			}
			// Now the verified one is held, and junk is offered in its place.
			for _, junk := range []WitnessReceiptRecord{
				{EventSAID: said, WitnessAID: witness, CesrSignature: forged, Event: event},
				{EventSAID: said, WitnessAID: witness, CesrSignature: good},
				{EventSAID: said, WitnessAID: witness, CesrSignature: "junk"},
			} {
				if err := st.SaveWitnessReceipt(junk); err == nil {
					t.Fatalf("junk was kept over a verified receipt: %+v", junk)
				}
			}
			held, _ := st.GetWitnessReceipts(said)
			if len(held) != 1 || held[0].CesrSignature != good {
				t.Fatalf("the verified receipt did not survive: %+v", held)
			}
		})
	}
}
