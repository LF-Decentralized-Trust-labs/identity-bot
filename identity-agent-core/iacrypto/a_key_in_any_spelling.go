package iacrypto

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Keys and signatures reach this Identity Agent spelled several ways: qb64
// from a KERI engine, base64 in one of four spellings depending on which
// language produced it, hex from older records. Deciding which spelling a
// value is in used to be done in four places, and they drifted: one took any
// 44-character value starting with D or B for qb64, which is also what one
// padded raw key in 32 looks like, and refused it. So it is decided here, once.

// base64Spellings are the four spellings of base64 in use. Where a value
// decodes under more than one, every one gives the same bytes.
var base64Spellings = []*base64.Encoding{
	base64.RawURLEncoding, base64.URLEncoding,
	base64.RawStdEncoding, base64.StdEncoding,
}

// DecodeBase64 decodes s written in any of the four base64 spellings.
func DecodeBase64(s string) ([]byte, error) {
	for _, enc := range base64Spellings {
		if raw, err := enc.DecodeString(s); err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("%q is not base64 in any of the standard alphabets", s)
}

// DecodeSized decodes s as exactly size raw bytes written in any base64
// spelling, or in hex when hexToo is set.
func DecodeSized(s string, size int, hexToo bool) ([]byte, error) {
	for _, enc := range base64Spellings {
		if raw, err := enc.DecodeString(s); err == nil && len(raw) == size {
			return raw, nil
		}
	}
	if hexToo {
		if raw, err := hex.DecodeString(s); err == nil && len(raw) == size {
			return raw, nil
		}
	}
	if hexToo {
		return nil, fmt.Errorf("not %d bytes in base64 or hex", size)
	}
	return nil, fmt.Errorf("not %d bytes in base64", size)
}

// Ed25519KeyCode reports whether key is an Ed25519 public key in qb64, and
// its derivation code: D (transferable) or B (non-transferable).
//
// Length and first character alone do not decide it. 32 raw bytes in padded
// base64 are 44 characters too, and one in 32 of them starts with D or B. The
// alphabet does: qb64 is base64url and never padded, while padded base64 of
// 32 bytes always ends in "=", so the two can never be confused.
func Ed25519KeyCode(key string) (code string, ok bool) {
	if len(key) != 44 || (key[0] != 'D' && key[0] != 'B') {
		return "", false
	}
	for i := 1; i < len(key); i++ {
		c := key[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "", false
		}
	}
	return key[:1], true
}

// DecodeEd25519Key returns the 32 raw bytes of an Ed25519 public key given in
// qb64 (code D or B, returned as code) or as raw bytes in any base64 spelling,
// or in hex when hexToo is set (code is then "").
func DecodeEd25519Key(key string, hexToo bool) (raw []byte, code string, err error) {
	if code, ok := Ed25519KeyCode(key); ok {
		raw, err := rawOfOneCharCode(key)
		if err != nil {
			return nil, "", fmt.Errorf("%q looks like a qb64 key and does not decode as one: %w", key, err)
		}
		return raw, code, nil
	}
	raw, err = DecodeSized(key, Ed25519PubkeyBytes, hexToo)
	if err != nil {
		return nil, "", fmt.Errorf("%q is not an Ed25519 public key in qb64, or as raw bytes: %w", key, err)
	}
	return raw, "", nil
}
