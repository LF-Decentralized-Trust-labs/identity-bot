package login

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"

	"identity-agent-core/iacrypto"
)

// BrowserKeyThumbprintLen is the length of a thumbprint: 32 bytes, unpadded
// base64url.
const BrowserKeyThumbprintLen = 43

// CheckBrowserKeyThumbprint refuses anything but one spelling of a SHA-256
// digest: 43 characters of base64url, no padding, the unused bits zero.
func CheckBrowserKeyThumbprint(s string) error {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(s) != BrowserKeyThumbprintLen || len(raw) != sha256.Size {
		return fmt.Errorf("a browser key thumbprint is 43 characters of base64url (an RFC 7638 SHA-256 digest)")
	}
	return nil
}

// ThumbprintP256 is the RFC 7638 thumbprint of the P-256 public key whose
// JWK coordinates are x and y (each 32 bytes, base64url as in the JWK): the
// SHA-256 of {"crv":"P-256","kty":"EC","x":...,"y":...} with the members in
// that order and no whitespace. It is the identifier a browser key has in a
// challenge and an assertion (ADR-066). Coordinates that are not exactly 32
// bytes in one spelling are refused.
func ThumbprintP256(x, y string) (string, error) {
	for _, c := range []string{x, y} {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(c)
		if err != nil || len(raw) != 32 {
			return "", fmt.Errorf("a P-256 coordinate is 32 bytes of unpadded base64url")
		}
	}
	sum := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// CanonicalChallengeBody is the exact text a challenge's signature covers. A
// party that has to check a challenge's signature without this package (a
// browser page, say) is given it beside the signature, verifies the signature
// over those bytes, and reads the challenge from the same bytes, so what it
// reads is what was signed.
func CanonicalChallengeBody(c ChallengeBundle) string { return canonicalChallengeBody(c) }

// BrowserKeyThumbprintOfMachineKey is the thumbprint (ThumbprintP256) of a
// P-256 key given in the form a machine key takes everywhere else in the core:
// its verkey, QB64. It is how a key that signed a statement is matched to the
// key a sign-in named by thumbprint (ADR-066, ADR-067). A key that is not a
// P-256 point has no browser-key thumbprint and is refused.
func BrowserKeyThumbprintOfMachineKey(verkey string) (string, error) {
	raw, err := iacrypto.KeyFromMachineVerkey(verkey)
	if err != nil {
		return "", err
	}
	var x, y *big.Int
	switch len(raw) {
	case 33:
		x, y = elliptic.UnmarshalCompressed(elliptic.P256(), raw)
	case 65:
		x, y = elliptic.Unmarshal(elliptic.P256(), raw)
	}
	if x == nil {
		return "", fmt.Errorf("the key is not a P-256 point")
	}
	enc := func(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, 32))) }
	return ThumbprintP256(enc(x), enc(y))
}
