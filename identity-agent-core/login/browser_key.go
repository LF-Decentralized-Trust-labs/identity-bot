package login

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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
