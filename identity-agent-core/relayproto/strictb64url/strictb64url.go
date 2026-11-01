// Package strictb64url is the one rule for reading unpadded base64url
// strictly, so that a value has exactly one string.
//
// It lives inside the relayproto module and imports nothing outside the
// standard library: relayproto must stay importable alone by a URL relay, and
// the core's iacrypto imports relayproto already, so both read it from here.
package strictb64url

import (
	"encoding/base64"
	"fmt"
)

// Decode decodes unpadded base64url of any length, strictly: only the
// base64url alphabet (so no padding, no standard-alphabet "+" or "/", and no
// line breaks, which the standard decoder skips) and zero spare bits in the
// last character.
func Decode(s string) ([]byte, error) {
	if !IsAlphabet(s) {
		return nil, fmt.Errorf("a character outside unpadded base64url")
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

// IsAlphabet reports whether every character of s is in the base64url
// alphabet, the only one qb64 uses. Padding is not in it.
func IsAlphabet(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
