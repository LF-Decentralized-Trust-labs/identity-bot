package iacrypto

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
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
	return decodeSized(s, size, hexToo, false)
}

// decodeSized is DecodeSized, decoding base64 strictly when strict is set:
// the bits left over in the last character must then be zero, so each
// spelling of a value has one string.
func decodeSized(s string, size int, hexToo, strict bool) ([]byte, error) {
	for _, enc := range base64Spellings {
		if strict {
			enc = enc.Strict()
		}
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
	if len(key) != 44 || (key[0] != 'D' && key[0] != 'B') || !isBase64URL(key) {
		return "", false
	}
	return key[:1], true
}

// isBase64URL reports whether every character of s is in the base64url
// alphabet, the only one qb64 uses. Padding is not in it.
func isBase64URL(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
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

// Signatures are told apart the same way. A 64-byte signature in qb64 is 88
// characters of base64url: a two-character code, or a one-character code and
// one character of index, standing in for two zero bytes. 64 raw bytes in
// padded base64 are 88 characters too, but always end in "==", so the
// alphabet decides it, never the first characters: one standard-base64
// signature in 64 starts with A, and one in 4096 with 0B.
const (
	sigQB64Len = 88
	sigBytes   = 64
)

// DecodeEd25519SignatureQB64 returns the 64 raw bytes of an unindexed Ed25519
// signature in qb64, code 0B, the form this Identity Agent signs in.
func DecodeEd25519SignatureQB64(sig string) ([]byte, error) {
	if len(sig) != sigQB64Len || sig[:2] != "0B" {
		return nil, fmt.Errorf("an Ed25519 signature in qb64 is 88 characters with the 0B code")
	}
	return decodeTwoCharCode(sig)
}

// DecodeIndexedEd25519SignatureQB64 returns an indexed Ed25519 signature in
// qb64: its code, A (the key at index in both the current and the next key
// list) or B (the current list only), the index, and the 64 raw bytes.
func DecodeIndexedEd25519SignatureQB64(sig string) (code byte, index int, raw []byte, err error) {
	if len(sig) != sigQB64Len || (sig[0] != 'A' && sig[0] != 'B') {
		return 0, 0, nil, fmt.Errorf("an indexed Ed25519 signature in qb64 is 88 characters with the A or B code")
	}
	index = strings.IndexByte(b64Chars, sig[1])
	if index < 0 {
		return 0, 0, nil, fmt.Errorf("the signature's index %q is not a base64url character", sig[1:2])
	}
	raw, err = decodeTwoCharCode(sig)
	if err != nil {
		return 0, 0, nil, err
	}
	return sig[0], index, raw, nil
}

// DecodeEd25519Signature returns the 64 raw bytes of an Ed25519 signature in
// qb64, or as raw bytes in any base64 spelling. An indexed qb64 signature is
// read only when indexedToo is set, and then index is its index and indexed
// is true.
func DecodeEd25519Signature(sig string, indexedToo bool) (raw []byte, index int, indexed bool, err error) {
	if len(sig) == sigQB64Len && isBase64URL(sig) {
		switch {
		case sig[:2] == "0B":
			raw, err = DecodeEd25519SignatureQB64(sig)
			return raw, 0, false, err
		case indexedToo && (sig[0] == 'A' || sig[0] == 'B'):
			_, index, raw, err = DecodeIndexedEd25519SignatureQB64(sig)
			return raw, index, true, err
		}
		// 88 characters of base64url are 66 bytes in every spelling, so this
		// is no raw signature either.
		return nil, 0, false, fmt.Errorf("the signature is in qb64 with a code that is not read here")
	}
	// Strict, as qb64 is: 64 bytes leave 4 bits over in the last character,
	// and read leniently they gave each spelling 16 strings.
	raw, err = decodeSized(sig, sigBytes, false, true)
	if err != nil {
		return nil, 0, false, fmt.Errorf("the signature is neither qb64 nor 64 raw bytes in base64: %w", err)
	}
	return raw, 0, false, nil
}

// decodeTwoCharCode recovers the 64 raw bytes behind a two-character code,
// or a one-character code and one character of index.
//
// TWO lead bytes, not one. The count is (3 - size mod 3) mod 3, and a 64-byte
// signature is 1 mod 3, so encoding prepends two zero bytes and the code then
// replaces the two base64 characters they produced. Decoding has to restore both
// and drop both — assuming one leaves the whole value shifted by a byte, which
// is a signature that never verifies and no error to say why.
//
// Strict: the lead bytes must be zero, and they are not entirely covered by
// the code. Its two characters stand for 12 bits; the third character carries
// the last 4 bits of the lead bytes and the first 2 of the signature. Leaving
// those 4 bits unchecked gave each signature 16 spellings that all verified.
func decodeTwoCharCode(qb64 string) ([]byte, error) {
	if len(qb64) != sigQB64Len {
		return nil, fmt.Errorf("a 64-byte value in qb64 is 88 characters, not %d", len(qb64))
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString("AA" + qb64[2:])
	if err != nil {
		return nil, fmt.Errorf("signature is not valid base64url: %w", err)
	}
	if len(raw) != sigBytes+2 {
		return nil, fmt.Errorf("expected 64 signature bytes, got %d", len(raw)-2)
	}
	if raw[0] != 0 || raw[1] != 0 {
		return nil, fmt.Errorf("the signature's lead bytes are not zero, so it is not in canonical qb64")
	}
	return raw[2:], nil
}
