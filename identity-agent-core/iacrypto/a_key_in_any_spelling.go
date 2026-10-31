package iacrypto

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
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
// spelling, or in lowercase hex when hexToo is set.
//
// Strict, so that each spelling of a value has exactly one string. Three
// things would otherwise give it more: the bits left over in the last base64
// character, which must be zero; the line breaks the standard decoder skips,
// which are refused; and the case of hex digits, where only lowercase, the
// form hex is written in, is read.
func DecodeSized(s string, size int, hexToo bool) ([]byte, error) {
	if !strings.ContainsAny(s, "\r\n") {
		for _, enc := range base64Spellings {
			if raw, err := enc.Strict().DecodeString(s); err == nil && len(raw) == size {
				return raw, nil
			}
		}
		if hexToo {
			if raw, err := DecodeHex(s); err == nil && len(raw) == size {
				return raw, nil
			}
		}
	}
	if hexToo {
		return nil, fmt.Errorf("not %d bytes in base64 or hex", size)
	}
	return nil, fmt.Errorf("not %d bytes in base64", size)
}

// ParseHexCount reads a count as KERI writes one, a sequence number or a
// threshold: lowercase hexadecimal with no leading zeros, "0" itself
// included, and no larger than an int32. strconv alone also takes uppercase
// and leading zeros, and fmt's %x stops at the first character it cannot read,
// so "2zz" read as 2. keri-go reads the counts in an event by the same rule.
func ParseHexCount(s string) (int, error) {
	n, err := strconv.ParseUint(s, 16, 31)
	if err != nil || strconv.FormatUint(n, 16) != s {
		return 0, fmt.Errorf("%q is not a count in lowercase hexadecimal without leading zeros", s)
	}
	return int(n), nil
}

// DecodeHex decodes lowercase hex, the case hex is written in, and only
// that: the standard decoder also reads uppercase, which gives a value one
// string per mix of cases.
func DecodeHex(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'F' {
			return nil, fmt.Errorf("hex is read in lowercase only")
		}
	}
	return hex.DecodeString(s)
}

// DecodeBase64URLSized decodes s as exactly size raw bytes in unpadded
// base64url and in no other spelling, for a format that names that one. It is
// strict as DecodeSized is, so the value has one string.
func DecodeBase64URLSized(s string, size int) ([]byte, error) {
	if len(s) != base64.RawURLEncoding.EncodedLen(size) {
		return nil, fmt.Errorf("not %d bytes in unpadded base64url", size)
	}
	raw, err := DecodeBase64URL(s)
	if err != nil {
		return nil, fmt.Errorf("not %d bytes in unpadded base64url: %w", size, err)
	}
	return raw, nil
}

// DecodeBase64URL decodes unpadded base64url of any length, strictly: only
// the base64url alphabet (so no padding and no line breaks, which the standard
// decoder skips) and zero spare bits in the last character. For a key or
// signature whose size depends on its kind; where the size is known,
// DecodeBase64URLSized also checks it.
func DecodeBase64URL(s string) ([]byte, error) {
	if !isBase64URL(s) {
		return nil, fmt.Errorf("a character outside unpadded base64url")
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
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
		raw, err := DecodeQB64(code, key, Ed25519PubkeyBytes)
		if err != nil {
			return nil, "", fmt.Errorf("%q looks like a qb64 key and does not decode as one: %w", key, err)
		}
		return raw, code, nil
	}
	raw, err = DecodeSized(key, Ed25519PubkeyBytes, hexToo)
	if err != nil {
		return nil, "", fmt.Errorf("%q is not an Ed25519 public key in qb64, or as raw bytes: %w", key, err)
	}
	if err := CheckEd25519PublicKey(raw); err != nil {
		return nil, "", fmt.Errorf("%q: %w", key, err)
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
	raw, err = DecodeSized(sig, sigBytes, false)
	if err != nil {
		return nil, 0, false, fmt.Errorf("the signature is neither qb64 nor 64 raw bytes in base64: %w", err)
	}
	return raw, 0, false, nil
}

// decodeTwoCharCode recovers the 64 raw bytes behind a two-character code,
// or a one-character code and one character of index: to the decoder the
// index is simply a second code character.
//
// TWO lead bytes, not one. A 64-byte signature is 1 mod 3, so encoding
// prepends two zero bytes and the code replaces the two base64 characters they
// produced. The third character carries the last 4 bits of those lead bytes,
// and DecodeQB64 requires them to be zero; unchecked, they gave each
// signature 16 spellings that all verified.
func decodeTwoCharCode(qb64 string) ([]byte, error) {
	if len(qb64) != sigQB64Len {
		return nil, fmt.Errorf("a 64-byte value in qb64 is 88 characters, not %d", len(qb64))
	}
	raw, err := DecodeQB64(qb64[:2], qb64, sigBytes)
	if err != nil {
		return nil, fmt.Errorf("the signature is not in canonical qb64: %w", err)
	}
	return raw, nil
}

// DecodeQB64 returns the size raw bytes of a fixed-size CESR value under code,
// and is the one place a qb64 key, identifier or signature is decoded.
//
// It reads only the canonical string, so each value has exactly one. That
// matters because a qb64 key is also a name: an identifier is compared as
// text, a witness is counted once, and a reader that accepted a second string
// for the same bytes would let one party appear as two. So it requires:
//
//   - the code, exactly;
//   - exactly the length the code and size make: the code, then the size and
//     its lead bytes in base64, less the characters the code stands in for;
//   - base64url only, which also refuses padding and the line breaks the
//     standard decoder would skip;
//   - zero lead bits. The lead bytes are (3 - size mod 3) mod 3 zero bytes
//     put in front so the value fills whole base64 groups. A code of one or
//     two characters stands in for the first characters they produce, but a
//     character is 6 bits and a byte 8, so the character after the code
//     carries the rest of them: 2 bits after a one-character code, 4 after a
//     two-character one. Unchecked, those gave every key 4 spellings and every
//     signature 16.
func DecodeQB64(code, qb64 string, size int) ([]byte, error) {
	if code == "" || size <= 0 {
		return nil, fmt.Errorf("decoding qb64 needs a code and a size")
	}
	if len(qb64) < len(code) || qb64[:len(code)] != code {
		return nil, fmt.Errorf("expected a %s value, got one starting %.4q", code, qb64)
	}
	if want, known := rawSizeForCode[code]; known && want != size {
		return nil, fmt.Errorf("code %s carries %d bytes, not %d", code, want, size)
	}
	lead := (3 - size%3) % 3
	stood := len(code) % 4 // base64 characters the code stands in for
	if stood*6 > lead*8 {
		return nil, fmt.Errorf("a %d-byte value cannot carry the %d-character code %s", size, len(code), code)
	}
	if want := len(code) - stood + (lead+size)/3*4; len(qb64) != want {
		return nil, fmt.Errorf("a %d-byte %s value is %d characters in qb64, not %d", size, code, want, len(qb64))
	}
	if !isBase64URL(qb64[len(code):]) {
		return nil, fmt.Errorf("a %s value has a character outside base64url, so it is not qb64", code)
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(strings.Repeat("A", stood) + qb64[len(code):])
	if err != nil {
		return nil, fmt.Errorf("a %s value is not valid base64url: %w", code, err)
	}
	if len(decoded) != lead+size {
		return nil, fmt.Errorf("expected %d bytes for a %s value, got %d", size, code, len(decoded)-lead)
	}
	for _, b := range decoded[:lead] {
		if b != 0 {
			return nil, fmt.Errorf("the %s value's lead bits are not zero, so it is not in canonical qb64", code)
		}
	}
	raw := decoded[lead:]
	// An Ed25519 key, transferable or not, must also be one point
	// (CheckEd25519PublicKey): every key read in qb64 is read here.
	if code == "D" || code == "B" {
		if err := CheckEd25519PublicKey(raw); err != nil {
			return nil, err
		}
	}
	return raw, nil
}
