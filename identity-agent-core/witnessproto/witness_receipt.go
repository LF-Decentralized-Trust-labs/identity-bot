package witnessproto

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"

	keri "github.com/grapeid/keri-go"
)

// The witness receipt, in the form keripy writes and reads (keri/core/eventing.py
// receipt, and Hab.witness in keri/app/habbing.py): five fields, signed over the
// serialised event it receipts with an indexed signature. It is the form ADR-070
// requires of every witness, so the Identity Agent and a hosted witness build
// and read it through this one implementation. The keripy vectors are in
// testdata/keripy_witness_receipts.json.

// KeripyWitnessReceiptVectors are receipts keripy 1.3.6 itself made for a real
// inception and later events, with the event bytes, the witness keys (seeds,
// for a test), the list in force and keripy's attachment, so a service that
// issues receipts tests itself against keripy and not against its own idea of
// the form. interop/make_witness_receipt_vectors.py makes them.
//
//go:embed testdata/keripy_witness_receipts.json
var KeripyWitnessReceiptVectors []byte

const receiptVersionPrefix = "KERI10JSON"

// ReceiptMessage is the rct a witness issues for an event: v, t, d, i, s in
// that order, as keripy serialises it. controllerAID is the event's controller,
// not the witness; who signed is the attached signature. sn is written in
// lowercase hex without leading zeros.
func ReceiptMessage(controllerAID string, sn uint64, eventSAID string) ([]byte, error) {
	if controllerAID == "" || eventSAID == "" {
		return nil, fmt.Errorf("a receipt names the controller and the event it receipts")
	}
	build := func(size int) ([]byte, error) {
		return marshalOrdered([][2]string{
			{"v", receiptVersionPrefix + fmt.Sprintf("%06x", size) + "_"},
			{"t", "rct"},
			{"d", eventSAID},
			{"i", controllerAID},
			{"s", strconv.FormatUint(sn, 16)},
		})
	}
	first, err := build(0)
	if err != nil {
		return nil, err
	}
	return build(len(first))
}

// marshalOrdered writes a flat JSON object with its fields in the given order,
// which encoding/json will not do for a map.
func marshalOrdered(fields [][2]string) ([]byte, error) {
	out := []byte{'{'}
	for i, f := range fields {
		if i > 0 {
			out = append(out, ',')
		}
		k, _ := json.Marshal(f[0])
		v, err := json.Marshal(f[1])
		if err != nil {
			return nil, err
		}
		out = append(out, k...)
		out = append(out, ':')
		out = append(out, v...)
	}
	return append(out, '}'), nil
}

// SignEventReceipt signs the serialised event as the witness whose key is made
// from seed, returning the indexed Ed25519 signature in qb64 that keripy's
// Hab.witness attaches. index is the witness's position in the controller's
// witness list.
func SignEventReceipt(rawEvent, seed []byte, index int) (string, error) {
	if len(rawEvent) == 0 {
		return "", fmt.Errorf("there is no event to receipt")
	}
	if len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("a witnessing key is %d bytes", ed25519.SeedSize)
	}
	if index < 0 || index > 63 {
		return "", fmt.Errorf("a witness index of %d does not fit a one-character index", index)
	}
	return keri.EncodeIndexedSignature(
		ed25519.Sign(ed25519.NewKeyFromSeed(seed), rawEvent), keri.SamePlace(index))
}

// WitnessKey is the key a witness identifier is made of, to compare or count
// by, and false when it is not a canonical non-transferable identifier. Two
// spellings of one witness give the same key.
func WitnessKey(witnessAID string) (string, bool) {
	pub, err := keri.MatterRaw("B", witnessAID, ed25519.PublicKeySize)
	if err != nil {
		return "", false
	}
	return string(pub), true
}

// WitnessPosition is where a witness stands in the controller's witness list,
// matched by key; -1 when it is not in the list.
func WitnessPosition(designated []string, witnessAID string) int {
	key, ok := WitnessKey(witnessAID)
	if !ok {
		return -1
	}
	for i, w := range designated {
		if k, ok := WitnessKey(w); ok && k == key {
			return i
		}
	}
	return -1
}

// IsEventSignedReceipt is whether a receipt signature is the current form, an
// indexed signature over the serialised event, rather than the earlier
// unindexed 0B one over the event's SAID string.
func IsEventSignedReceipt(cesrSig string) bool {
	return len(cesrSig) == 88 && cesrSig[0] == 'A'
}

// VerifyEventReceipt checks a witness's receipt of an event in either form in
// circulation.
//
// The current form is the indexed signature over the serialised event. When
// designated is given its index must be the witness's position in that list: an
// index naming another place is a signature keripy files under another witness.
// The earlier form, an unindexed 0B signature over the SAID string, is read
// for as long as witnesses still send it (ADR-070, Migration), and nothing
// issues it any more.
func VerifyEventReceipt(witnessAID string, rawEvent []byte, eventSAID, cesrSig string, designated []string) error {
	if witnessAID == "" || cesrSig == "" || (len(rawEvent) == 0 && eventSAID == "") {
		return fmt.Errorf("a receipt needs a witness, an event and a signature")
	}
	if _, ok := WitnessKey(witnessAID); !ok {
		return fmt.Errorf("%q is not a non-transferable witness identifier, so its receipts "+
			"cannot be checked without resolving a key log first", witnessAID)
	}
	if !IsEventSignedReceipt(cesrSig) {
		raw, err := keri.MatterRaw("0B", cesrSig, ed25519.SignatureSize)
		if err != nil {
			return fmt.Errorf("the receipt signature does not decode: %w", err)
		}
		if eventSAID == "" || keri.VerifyUnderKey(witnessAID, []byte(eventSAID), "", raw) != nil {
			return fmt.Errorf("the receipt was not signed by %s, so that witness did not issue it", witnessAID)
		}
		return nil
	}
	if len(rawEvent) == 0 {
		return fmt.Errorf("a receipt signed over the event cannot be checked without the event")
	}
	sig, err := keri.ParseIndexedSignature(cesrSig)
	if err != nil {
		return fmt.Errorf("the receipt signature does not decode: %w", err)
	}
	if sig.Code != "A" {
		return fmt.Errorf("a witness receipt is signed with the A code, not %q", sig.Code)
	}
	if designated != nil {
		if at := WitnessPosition(designated, witnessAID); at != sig.At.Index {
			return fmt.Errorf("the receipt is indexed %d and %s stands at %d in the witness list",
				sig.At.Index, witnessAID, at)
		}
	}
	if keri.VerifyUnderKey(witnessAID, rawEvent, sig.Code, sig.Raw) != nil {
		return fmt.Errorf("the receipt was not signed by %s over this event", witnessAID)
	}
	return nil
}
