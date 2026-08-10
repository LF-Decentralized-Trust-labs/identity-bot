package witness

import (
	"fmt"
	"sync"

	"identity-agent-core/drivers"
	"identity-agent-core/secureenclave"

	keri "github.com/grapeid/keri-go"
)

// The key a witness signs receipts with, and why a witness has one of its own.
//
// A receipt is an outsider's statement that it saw a particular event from a
// particular controller. Its whole value is that somebody other than the
// controller can be shown to have said it — so it has to be signed by a key
// that is not the controller's and that a stranger can check.
//
// The key is NON-TRANSFERABLE, which is what makes checking a receipt possible
// without a lookup. A non-transferable identifier IS its verifying key: given
// the witness identifier from an event's witness list, a verifier can check the
// signature immediately, with no key log to fetch and no current-key question to
// resolve. A transferable identifier would mean fetching that witness's log and
// working out which key was in force at the time — for every receipt, from every
// verifier, forever. It would also mean a witness could rotate away from a key
// and leave its old receipts unverifiable.
//
// It is a different key from the identity this agent controls, deliberately.
// Witnessing is a service performed for other people, and a receipt signed by
// the same key that signs this agent's own events would tie the two together in
// public: anybody collecting receipts could see which identity issued them.
//
// It is held by the platform signer, so where the hardware allows it the private
// half never leaves the enclave.

// receiptSigner is the witness key for this agent, resolved once.
type receiptSigner struct {
	once   sync.Once
	signer secureenclave.PlatformSigner
	aid    string
	err    error
}

// WitnessKey returns this agent's witness identifier and the signer behind it.
//
// The identifier is the qb64 form of the public key under the non-transferable
// Ed25519 code, so it is both the name of this witness and the key its receipts
// verify against.
func (s *Service) WitnessKey() (string, secureenclave.PlatformSigner, error) {
	s.receipt.once.Do(func() {
		signer := s.ReceiptSigner
		if signer == nil {
			signer = secureenclave.NewPlatformSigner(s.DataDir)
		}
		if signer == nil || !signer.Available() {
			s.receipt.err = fmt.Errorf("this agent has no key to sign receipts with, so it " +
				"cannot witness for anybody")
			return
		}
		pub, err := signer.PublicKey()
		if err != nil {
			s.receipt.err = fmt.Errorf("could not read the witness key: %w", err)
			return
		}
		if len(pub) != 32 {
			s.receipt.err = fmt.Errorf("the witness key is %d bytes; Ed25519 keys are 32", len(pub))
			return
		}
		aid, err := keri.MatterQB64(keri.CodeEd25519N, pub)
		if err != nil {
			s.receipt.err = fmt.Errorf("could not encode the witness key: %w", err)
			return
		}
		s.receipt.signer = signer
		s.receipt.aid = aid
	})
	return s.receipt.aid, s.receipt.signer, s.receipt.err
}

// SignReceipt produces this witness's signature over an event identifier.
//
// The signature is over the event's SAID, which is what a KERI receipt covers:
// the digest names exactly one event, so a receipt cannot be moved to a
// different event, and a verifier needs nothing but the digest and the witness
// identifier to check it.
func (s *Service) SignReceipt(eventSAID string) (witnessAID, cesrSig string, err error) {
	if eventSAID == "" {
		return "", "", fmt.Errorf("a receipt must name the event it covers")
	}
	aid, signer, err := s.WitnessKey()
	if err != nil {
		// Refused rather than issuing something unsigned. A receipt that proves
		// nothing is worse than no receipt: it is counted towards a threshold
		// by everyone who receives it, so it makes a log look corroborated
		// while corroborating nothing.
		return "", "", err
	}
	raw, err := signer.Sign([]byte(eventSAID))
	if err != nil {
		return "", "", fmt.Errorf("could not sign the receipt: %w", err)
	}
	qb64, err := keri.MatterQB64(keri.CodeEd25519Sig, raw)
	if err != nil {
		return "", "", fmt.Errorf("could not encode the receipt signature: %w", err)
	}
	return aid, qb64, nil
}

// VerifyReceipt checks a receipt against the witness that claims to have issued
// it.
//
// Defined in the drivers package and re-exported here: the key-log validator
// needs exactly the same check when it counts receipts, and two copies of a
// signature check are two chances for them to disagree about what counts.
func VerifyReceipt(witnessAID, eventSAID, cesrSig string) error {
	return drivers.VerifyReceipt(witnessAID, eventSAID, cesrSig)
}
