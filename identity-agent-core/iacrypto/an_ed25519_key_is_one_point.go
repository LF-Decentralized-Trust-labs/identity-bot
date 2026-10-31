package iacrypto

import (
	"bytes"
	"fmt"

	"filippo.io/edwards25519"
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
func CheckEd25519PublicKey(raw []byte) error {
	if len(raw) != Ed25519PubkeyBytes {
		return fmt.Errorf("an Ed25519 public key is %d bytes, not %d", Ed25519PubkeyBytes, len(raw))
	}
	p, err := new(edwards25519.Point).SetBytes(raw)
	if err != nil {
		return fmt.Errorf("the Ed25519 public key is not a point on the curve")
	}
	if !bytes.Equal(p.Bytes(), raw) {
		return fmt.Errorf("the Ed25519 public key is not in its canonical encoding")
	}
	if new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return fmt.Errorf("the Ed25519 public key is of small order, so a signature under it proves nothing")
	}
	return nil
}
