package witness

import (
	"crypto/ed25519"
	"fmt"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"

	keri "github.com/grapeid/keri-go"
)

// A receipt's index is the witness's place in the list in force at the event it
// receipts. An earlier event sent again after a rotation that moved the witness
// is receipted at its own place, not at the place the witness holds now.
func TestARepeatedEarlierEventIsReceiptedAtItsOwnPlace(t *testing.T) {
	s := witnessFor(t)
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 9
	ours := iacrypto.NonTransferableAIDQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	other := iacrypto.NonTransferableAIDQB64(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey))
	s.OurWitnessAID = func() (string, error) { return ours, nil }
	sign := eventSignerFor(seed)
	failing := true
	s.SignEventReceipt = func(raw []byte, designated []string) (string, string, error) {
		if failing {
			return "", "", fmt.Errorf("no key just now")
		}
		return sign(raw, designated)
	}

	o := newOwner(t)
	toad := 1
	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{pub(t, o.now)}, NextDigests: []string{digest(t, o.next)},
		Witnesses: []string{other, ours}, Toad: &toad, Derivation: "self-addressing",
	})
	if err != nil {
		t.Fatal(err)
	}
	icpEv := parsed(t, icp)
	aid := icpEv.Identifier
	witnessesFor(t, s, aid)
	icpSig := signAt(t, o.now, icp, keri.SamePlace(0))
	// Held, not receipted: no key to sign with.
	if _, err := s.ReceiveSignedEvent(aid, icp, []string{icpSig}); err == nil {
		t.Fatal("the event was receipted without a key")
	}
	// Cutting the other witness moves this one to place 0.
	rot, err := keri.BuildRotation(keri.RotationInput{
		Prefix: aid, PriorSAID: icpEv.SAID, SN: 1, Keys: []string{pub(t, o.next)},
		NextDigests: []string{digest(t, o.now)}, PriorWitnesses: []string{other, ours},
		Cuts: []string{other}, Toad: &toad,
	})
	if err != nil {
		t.Fatal(err)
	}
	failing = false
	out, err := s.ReceiveSignedEvent(aid, rot, []string{signAt(t, o.next, rot, keri.SamePlace(0))})
	if err != nil {
		t.Fatalf("the rotation was refused: %v", err)
	}
	if _, idx := indexOf(t, out); idx != 0 {
		t.Fatalf("after the rotation the witness stands at 0, the receipt is indexed %d", idx)
	}

	out, err = s.ReceiveSignedEvent(aid, icp, []string{icpSig})
	if err != nil {
		t.Fatalf("the earlier event was refused when sent again: %v", err)
	}
	sig, idx := indexOf(t, out)
	if idx != 1 {
		t.Fatalf("the inception named the witness at place 1; its receipt is indexed %d", idx)
	}
	if err := drivers.VerifyEventReceipt(ours, icp, icpEv.SAID, sig, []string{other, ours}); err != nil {
		t.Fatalf("the receipt does not verify at the inception's own list: %v", err)
	}
}

func indexOf(t *testing.T, out map[string]interface{}) (string, int) {
	t.Helper()
	sig, _ := out["cesr_signature"].(string)
	_, idx, _, err := iacrypto.DecodeIndexedEd25519SignatureQB64(sig)
	if err != nil {
		t.Fatalf("no indexed signature: %v", err)
	}
	return sig, idx
}
