package iacrypto

import (
	keri "github.com/grapeid/keri-go"
)

// CheckEd25519PublicKey refuses an Ed25519 public key that names no single
// signer: one that is not a point on the curve, one written in a
// non-canonical encoding, and one of small order.
//
// Ed25519 verifiers differ on exactly these keys. Go's crypto/ed25519 is
// cofactorless and takes any point, so a small-order key — the identity
// point, say — has a signature that verifies over every message, and a
// non-canonical encoding is a second string for a key another verifier reads
// as different bytes. Refusing them where a key is read, rather than leaving
// it to whichever verifier sees it, gives every verifier the same set of keys
// to disagree over: none.
//
// The rule is written once, in keri-go (keri.CheckEd25519PublicKey), which
// reads every key in a key event log through it; this is that rule for the
// keys identity-bot reads without keri-go.
func CheckEd25519PublicKey(raw []byte) error {
	return keri.CheckEd25519PublicKey(raw)
}
