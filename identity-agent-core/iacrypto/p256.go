package iacrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// NIST P-256 keys, alongside Ed25519.
//
// WHY A SECOND CURVE AT ALL, when one is simpler. Because of what a machine's
// key has to be: held in hardware that will not give it up. Discrete security
// chips do RSA-2048 and P-256; none of them does Ed25519, and none is coming.
// So a machine either signs with a key that lives in a file — copyable, and
// therefore a key that says "something that once had access to this disk"
// rather than "this machine" — or it signs with P-256.
//
// THE ASYMMETRY IS DELIBERATE AND BOUNDED. People, organisations and instances
// stay on Ed25519. Only a MACHINE's own key moves, and that is defensible
// precisely because a machine's key is disposable: nobody writes down recovery
// words for it, and losing it costs a re-pairing rather than an identity.
//
// P-256 keys are carried compressed — 33 bytes, one byte of parity and the
// x coordinate — because that is what the CESR code for this curve is sized
// for and what a chip hands back.

// P256VerkeyCode is the CESR code for a P-256 verification key.
const P256VerkeyCode = "1AAJ"

// P256SignatureCode is the CESR code for a P-256 signature.
const P256SignatureCode = "0I"

// P256PublicKeySize is a compressed point: one parity byte and the x coordinate.
const P256PublicKeySize = 33

// P256VerkeyQB64 encodes a compressed P-256 public key as CESR.
func P256VerkeyQB64(compressed []byte) (string, error) {
	if len(compressed) != P256PublicKeySize {
		return "", fmt.Errorf("a P-256 key is %d bytes compressed, got %d",
			P256PublicKeySize, len(compressed))
	}
	return MatterFixedQB64(P256VerkeyCode, compressed)
}

// KeyFromP256VerkeyQB64 recovers the compressed point from its CESR form.
func KeyFromP256VerkeyQB64(qb64 string) ([]byte, error) {
	if len(qb64) < len(P256VerkeyCode) || qb64[:len(P256VerkeyCode)] != P256VerkeyCode {
		return nil, fmt.Errorf("%q is not a P-256 verification key", qb64)
	}
	raw, err := DecodeLargeFixed(P256VerkeyCode, qb64, P256PublicKeySize)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// ParseP256PublicKey turns a compressed point into a usable key.
//
// It refuses a point that is not on the curve. A point off the curve is not a
// key that verifies nothing — it is a key some implementations will happily
// "verify" against, which is worse.
func ParseP256PublicKey(compressed []byte) (*ecdsa.PublicKey, error) {
	if len(compressed) != P256PublicKeySize {
		return nil, fmt.Errorf("a P-256 key is %d bytes compressed, got %d",
			P256PublicKeySize, len(compressed))
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if x == nil || y == nil {
		return nil, fmt.Errorf("this is not a point on P-256")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// CompressP256PublicKey is the inverse, for a key coming out of hardware.
func CompressP256PublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil, fmt.Errorf("no key to compress")
	}
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("this key is not on P-256")
	}
	return elliptic.MarshalCompressed(elliptic.P256(), pub.X, pub.Y), nil
}

// VerifyP256 checks a signature in the form KERI carries it.
//
// Fixed-width r||s, 32 bytes each, NOT the ASN.1 DER a Go or PKCS#11 signer
// hands back. The distinction is the whole reason this function exists rather
// than a call to ecdsa.VerifyASN1: a DER signature is variable length and would
// not fit a fixed CESR code, so the conversion has to happen somewhere and it
// belongs next to the code that defines the wire form.
func VerifyP256(pub *ecdsa.PublicKey, message, sig []byte) bool {
	if pub == nil || len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	sum := sha256.Sum256(message)
	digest := sum[:]
	return ecdsa.Verify(pub, digest, r, s)
}
