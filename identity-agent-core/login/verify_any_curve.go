package login

import (
	"encoding/base64"
	"fmt"
	"strings"

	"identity-agent-core/iacrypto"
)

// Verifying a signature against whatever curve the key says it is.
//
// WHY THIS EXISTS RATHER THAN A WIDER DecodeVerkey. That function returns raw
// bytes, and raw bytes cannot say which curve they belong to — every caller
// then has to know, and ten of them currently assume Ed25519 by construction.
// Widening it would push that question outward to all ten.
//
// So the question is answered once, here, where the answer is actually needed:
// a signature is checked against a key, and the key states its own curve in the
// form it is carried in. Callers that merely want to know a key is well formed
// keep using DecodeVerkey; callers that verify use this.
//
// WHAT IS ON WHICH CURVE, and why it is not uniform. People, organisations and
// instances sign with Ed25519. A MACHINE's own key is P-256, because the chips
// that hold a key without giving it up do P-256 and not Ed25519 — so the choice
// is between a curve the hardware supports and a key in a file that can be
// copied. The asymmetry is bounded to machines, whose keys are disposable:
// losing one costs a re-pairing, not an identity.

// VerifyStringAnyCurve checks a signature against a key, on whichever curve
// that key declares.
//
// The key is passed in the form it is stored and published, not as bytes,
// because that form is what carries the curve.
func VerifyStringAnyCurve(body, sigQB64, publicKey string) (bool, error) {
	key := strings.TrimSpace(publicKey)
	if key == "" {
		return false, fmt.Errorf("no public key to check against")
	}

	if strings.HasPrefix(key, iacrypto.P256VerkeyCode) {
		compressed, err := iacrypto.KeyFromP256VerkeyQB64(key)
		if err != nil {
			return false, err
		}
		pub, err := iacrypto.ParseP256PublicKey(compressed)
		if err != nil {
			return false, err
		}
		sig, err := decodeP256Signature(sigQB64)
		if err != nil {
			return false, err
		}
		return iacrypto.VerifyP256(pub, []byte(body), sig), nil
	}

	// Everything else is Ed25519, which is what every identity that is not a
	// machine signs with.
	pub, err := DecodeVerkey(key)
	if err != nil {
		return false, err
	}
	return VerifyString(body, sigQB64, pub)
}

// decodeP256Signature reads a signature in the fixed-width form CESR carries.
//
// r||s, 32 bytes each. Not the ASN.1 DER a signer hands back: DER is variable
// length and does not fit a fixed code, so the conversion happens at the edge
// where the wire form is defined, and this is the reading half of it.
func decodeP256Signature(sigQB64 string) ([]byte, error) {
	sig := strings.TrimSpace(sigQB64)
	if !strings.HasPrefix(sig, iacrypto.P256SignatureCode) {
		return nil, fmt.Errorf("a P-256 key needs a P-256 signature; this one is not marked as one")
	}
	// One code character short of a base64 boundary, so the leading pad is
	// restored before decoding — the same shape decodeMatterRaw handles for
	// Ed25519 signatures.
	body := sig[len(iacrypto.P256SignatureCode):]
	raw, err := base64.RawURLEncoding.DecodeString(strings.Repeat("A", len(iacrypto.P256SignatureCode)) + body)
	if err != nil {
		return nil, fmt.Errorf("signature is not valid base64url: %w", err)
	}
	if len(raw) < 64 {
		return nil, fmt.Errorf("a P-256 signature is 64 bytes, got %d", len(raw))
	}
	return raw[len(raw)-64:], nil
}
