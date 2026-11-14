package drivers

import (
	"fmt"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"identity-agent-core/iacrypto"
)

// The witness receipt, in the form keripy writes and reads. See
// docs/adr/070-witness-classes-and-valid-receipts.md.

// The receipt itself is built, signed and checked by witnessproto, the one
// implementation a hosted witness shares; these are the names this package's
// callers already use.

// ReceiptMessage is witnessproto.ReceiptMessage.
func ReceiptMessage(controllerAID string, sn uint64, eventSAID string) ([]byte, error) {
	return witnessproto.ReceiptMessage(controllerAID, sn, eventSAID)
}

// SignEventReceipt is witnessproto.SignEventReceipt.
func SignEventReceipt(rawEvent []byte, seed []byte, index int) (string, error) {
	return witnessproto.SignEventReceipt(rawEvent, seed, index)
}

// WitnessPosition is witnessproto.WitnessPosition.
func WitnessPosition(designated []string, witnessAID string) int {
	return witnessproto.WitnessPosition(designated, witnessAID)
}

// VerifyEventReceipt is witnessproto.VerifyEventReceipt.
func VerifyEventReceipt(witnessAID string, rawEvent []byte, eventSAID, cesrSig string, designated []string) error {
	return witnessproto.VerifyEventReceipt(witnessAID, rawEvent, eventSAID, cesrSig, designated)
}

// IsEventSignedReceipt is witnessproto.IsEventSignedReceipt.
func IsEventSignedReceipt(cesrSig string) bool {
	return witnessproto.IsEventSignedReceipt(cesrSig)
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
