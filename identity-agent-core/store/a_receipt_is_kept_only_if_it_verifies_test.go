package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/iacrypto"

	keri "github.com/grapeid/keri-go"
)

func signReceipt(said string, priv ed25519.PrivateKey) string {
	sig, _ := keri.MatterQB64(keri.CodeEd25519Sig, ed25519.Sign(priv, []byte(said)))
	return sig
}

// Both stores keep only a receipt the named witness signed, read back only
// receipts that verify, and let a verified receipt replace a junk one that
// was kept before the check existed.
func TestBothStoresKeepOnlyReceiptsThatVerify(t *testing.T) {
	const said = "Ean-event"
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	witness := iacrypto.NonTransferableAIDQB64(pub)
	real := signReceipt(said, priv)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forged := signReceipt(said, other)

	sqlite, err := NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fileDir := t.TempDir()
	file, err := NewFileStore(fileDir)
	if err != nil {
		t.Fatal(err)
	}
	plantJunk := map[string]func(){
		"sqlite": func() {
			if _, err := sqlite.DB().Exec(`INSERT INTO witness_receipts (event_said, witness_aid, cesr_signature, received_at)
				VALUES (?, ?, 'junk', '')`, said, witness); err != nil {
				t.Fatal(err)
			}
		},
		"file": func() {
			body := `{"` + said + `":[{"event_said":"` + said + `","witness_aid":"` + witness + `","cesr_signature":"junk","received_at":""}]}`
			if err := os.WriteFile(filepath.Join(fileDir, "witness_receipts.json"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	type receipts interface {
		SaveWitnessReceipt(WitnessReceiptRecord) error
		GetWitnessReceipts(string) ([]WitnessReceiptRecord, error)
	}
	for name, st := range map[string]receipts{"sqlite": sqlite, "file": file} {
		t.Run(name, func(t *testing.T) {
			err := st.SaveWitnessReceipt(WitnessReceiptRecord{EventSAID: said, WitnessAID: witness, CesrSignature: forged})
			if !errors.Is(err, ErrReceiptDoesNotVerify) {
				t.Fatalf("a receipt signed by another key was not refused: %v", err)
			}
			plantJunk[name]()
			if held, _ := st.GetWitnessReceipts(said); len(held) != 0 {
				t.Fatalf("a junk receipt was read back: %+v", held)
			}
			if err := st.SaveWitnessReceipt(WitnessReceiptRecord{EventSAID: said, WitnessAID: witness, CesrSignature: real}); err != nil {
				t.Fatal(err)
			}
			held, _ := st.GetWitnessReceipts(said)
			if len(held) != 1 || held[0].CesrSignature != real {
				t.Fatalf("the real receipt did not replace the junk one: %+v", held)
			}
		})
	}
}
