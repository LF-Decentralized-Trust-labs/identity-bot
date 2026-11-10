package drivers

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strconv"

	keri "github.com/grapeid/keri-go"
	"identity-agent-core/iacrypto"
)

// The witness receipt, in the form keripy writes and reads (keri/core/eventing.py
// receipt, and Hab.witness in keri/app/habbing.py): five fields, signed over the
// serialised event it receipts with an indexed signature. A receipt in this form
// is verifiable by software written against the KERI specification and nothing
// of ours. See docs/adr/070-witness-classes-and-valid-receipts.md.

// receiptVersionPrefix is the version string of a JSON receipt up to the size.
const receiptVersionPrefix = "KERI10JSON"

// ReceiptMessage is the rct a witness issues for an event: v, t, d, i, s in that
// order, as keripy serialises it.
//
// controllerAID is the identifier of the event's controller, not the witness's:
// the receipt says whose event it is, and who signed it is carried by the
// attached signature. eventSAID is the receipted event's SAID. sn is its
// sequence number, written in lowercase hex without leading zeros.
func ReceiptMessage(controllerAID string, sn uint64, eventSAID string) ([]byte, error) {
	if controllerAID == "" || eventSAID == "" {
		return nil, fmt.Errorf("a receipt names the controller and the event it receipts")
	}
	// The size is of the whole message and is written inside it, six hex digits
	// wide, so it is fixed once and the length it needs does not change.
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
// Hab.witness attaches: index is the witness's position in the controller's
// witness list.
func SignEventReceipt(rawEvent []byte, seed []byte, index int) (string, error) {
	if len(rawEvent) == 0 {
		return "", fmt.Errorf("there is no event to receipt")
	}
	if len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("a witnessing key is %d bytes", ed25519.SeedSize)
	}
	if index < 0 || index > 63 {
		return "", fmt.Errorf("a witness index of %d does not fit a one-character index", index)
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), rawEvent)
	return iacrypto.MatterIndexedSigQB64("A", index, sig, 88)
}

// WitnessPosition is where a witness stands in the controller's witness list,
// by its key, so two spellings of one witness are the same position; -1 when it
// is not in the list.
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

// VerifyEventReceipt checks a witness's receipt of an event, in either of the
// two forms in circulation.
//
// The current form is the indexed signature over the serialised event, which
// is the one keripy makes and reads. When designated is given, its index must
// be the witness's position in that list: an index that names another place is
// a signature keripy files under another witness.
//
// The earlier form, an unindexed 0B signature over the event's SAID string, is
// read for as long as witnesses still send it, and only then. It proves the
// witness signed the digest, which commits to the event, but nobody outside
// this code can check it. Nothing issues it any more.
func VerifyEventReceipt(witnessAID string, rawEvent []byte, eventSAID, cesrSig string, designated []string) error {
	if witnessAID == "" || cesrSig == "" || (len(rawEvent) == 0 && eventSAID == "") {
		return fmt.Errorf("a receipt needs a witness, an event and a signature")
	}
	if IsEventSignedReceipt(cesrSig) {
		if len(rawEvent) == 0 {
			return fmt.Errorf("a receipt signed over the event cannot be checked without the event")
		}
		if _, err := iacrypto.KeyFromNonTransferableAID(witnessAID); err != nil {
			return fmt.Errorf("%q is not a non-transferable witness identifier: %w", witnessAID, err)
		}
		_, index, raw, err := iacrypto.DecodeIndexedEd25519SignatureQB64(cesrSig)
		if err != nil {
			return fmt.Errorf("the receipt signature does not decode: %w", err)
		}
		if designated != nil {
			if at := WitnessPosition(designated, witnessAID); at != index {
				return fmt.Errorf("the receipt is indexed %d and %s stands at %d in the witness list",
					index, witnessAID, at)
			}
		}
		if keri.VerifyUnderKey(witnessAID, rawEvent, "", raw) != nil {
			return fmt.Errorf("the receipt was not signed by %s over this event", witnessAID)
		}
		return nil
	}
	return VerifyReceipt(witnessAID, eventSAID, cesrSig)
}

// IsEventSignedReceipt is whether a receipt signature is the current form, an
// indexed signature over the serialised event, rather than the earlier one over
// the SAID string.
func IsEventSignedReceipt(cesrSig string) bool {
	return len(cesrSig) == 88 && cesrSig[0] == 'A'
}

// CheckReceiptShape is what can be said of a receipt signed over the event when
// the event is not at hand: it names a witness that is its own key, and its
// signature is an indexed Ed25519 signature that decodes. Whether that witness
// signed that event is VerifyEventReceipt's question, asked wherever the event
// is read.
func CheckReceiptShape(witnessAID, cesrSig string) error {
	if _, err := iacrypto.KeyFromNonTransferableAID(witnessAID); err != nil {
		return fmt.Errorf("%q is not a non-transferable witness identifier: %w", witnessAID, err)
	}
	if !IsEventSignedReceipt(cesrSig) {
		return fmt.Errorf("the receipt signature is not an indexed Ed25519 signature")
	}
	if _, _, _, err := iacrypto.DecodeIndexedEd25519SignatureQB64(cesrSig); err != nil {
		return fmt.Errorf("the receipt signature is not an indexed Ed25519 signature")
	}
	return nil
}
