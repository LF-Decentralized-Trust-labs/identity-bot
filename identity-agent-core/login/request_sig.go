package login

import (
	"fmt"
	"strings"

	"identity-agent-core/iacrypto"
)

// Signing over an arbitrary canonical string, for callers outside the Ask flow.
//
// The Ask helpers above sign a canonicalised JSON document. Authorising an HTTP
// request needs the same Ed25519 + CESR qb64 primitives over a string the caller
// composes itself, so these expose them without inventing a second crypto path.

// SignString signs body with a 32-byte Ed25519 seed and returns a CESR qb64
// signature (code 0B).
func SignString(body string, seed []byte) (string, error) {
	sig, _, err := signUTF8(body, seed)
	return sig, err
}

// VerifyString verifies a CESR qb64 signature over body against a raw 32-byte
// Ed25519 public key.
func VerifyString(body, sigQB64 string, pub []byte) (bool, error) {
	return verifyUTF8(body, sigQB64, pub)
}

// DecodeVerkey turns a stored public key into raw Ed25519 bytes. Keys reach us
// in more than one encoding depending on which path minted them — CESR qb64
// from the KERI driver, plain base64 from the mobile core, hex from older
// records — so all three are accepted rather than failing on a format detail.
func DecodeVerkey(key string) ([]byte, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, fmt.Errorf("empty public key")
	}
	// Both Ed25519 qb64 codes: "B" is Ed25519N, a non-transferable key, and the
	// KERI driver mints one for an identity that will never rotate. Which
	// spelling a key is in is iacrypto's to decide, in one place.
	raw, _, err := iacrypto.DecodeEd25519Key(key, true)
	if err != nil {
		return nil, fmt.Errorf("public key is not a recognisable Ed25519 key")
	}
	return raw, nil
}
