package iacrypto

import (
	"encoding/base64"
	"fmt"
)

const (
	CipherSuiteIAHybrid1 = "IA-HYBRID-1"
	CESRMLDSA65Verkey    = "1PDA"
	CESRMLDSA65Sig       = "1PDS"
	CESRMLKEM768Encap    = "1PKM"
	CESRX25519Pubkey     = "1PXB"
	MLDSA65VerkeyBytes   = 1952
	MLDSA65SigBytes      = 3309
	MLKEM768EncapBytes   = 1184
	X25519PubkeyBytes    = 32
	Ed25519PubkeyBytes   = 32
	Ed25519SigBytes      = 64
	CtrControllerIdxSigs = "-A"
	C2Message            = "m63-c2-hybrid-signature-golden-vector"
)

var (
	C2Ed25519Seed = func() []byte {
		out := make([]byte, 32)
		for i := range out {
			out[i] = byte((i + 0x21) % 256)
		}
		return out
	}()
	C2MLDSASeed = []byte("m63-c2-hybrid-signature-golden!!")
)

// keri Base64 index alphabet (matches keripy intToB64).
var b64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func intToB64(i int, length int) string {
	d := make([]byte, 0, length)
	for length > 0 && (len(d) < length || i > 0) {
		d = append([]byte{b64Chars[i%64]}, d...)
		i /= 64
	}
	for len(d) < length {
		d = append([]byte{'A'}, d...)
	}
	return string(d)
}

func b64ToInt(s string) int {
	n := 0
	for _, c := range s {
		n = n*64 + int(bytesIndexRune(b64Chars, c))
	}
	return n
}

func bytesIndexRune(s string, r rune) int {
	for i, c := range s {
		if c == r {
			return i
		}
	}
	return 0
}

// MatterFixedQB64 encodes fixed-size CESR material (keri 1.1.17 Matter._infil).
func MatterFixedQB64(code string, raw []byte) (string, error) {
	if len(code) < 1 {
		return "", fmt.Errorf("matter code required")
	}
	ps := (3 - (len(raw) % 3)) % 3
	cs := len(code)
	padded := make([]byte, ps+len(raw))
	copy(padded[ps:], raw)
	b64 := base64.RawURLEncoding.EncodeToString(padded)
	if cs%4 > len(b64) {
		return "", fmt.Errorf("invalid matter encoding for code %q", code)
	}
	return code + b64[cs%4:], nil
}

func EncodeLargeFixed(code string, raw []byte, expectedLen int) (string, error) {
	if len(code) != 4 {
		return "", fmt.Errorf("provisional CESR code must be 4 chars, got %q", code)
	}
	if expectedLen > 0 && len(raw) != expectedLen {
		return "", fmt.Errorf("expected %d raw bytes for %s, got %d", expectedLen, code, len(raw))
	}
	return code + base64.RawURLEncoding.EncodeToString(raw), nil
}

// NonTransferableAIDQB64 encodes a raw Ed25519 public key as a CESR
// non-transferable identifier (code "B").
//
// A non-transferable identifier IS its verifying key, so anyone holding the
// identifier can check a signature made under it without fetching anything —
// no key history, no address, no network. That is exactly what a witness needs
// to be: the point of a receipt is that a third party can check it, and a
// receipt whose key must first be looked up somewhere just moves the question
// to whoever answers the lookup.
//
// The trade is that such an identifier cannot rotate — its key is fixed for
// life. For a witness that is the correct trade, because a witness is a role
// something performs rather than a party with a history, and replacing the key
// means naming a different witness.
func NonTransferableAIDQB64(pub []byte) string {
	s, err := MatterFixedQB64("B", pub)
	if err != nil {
		return ""
	}
	return s
}

// KeyFromNonTransferableAID recovers the verifying key a non-transferable
// identifier is made of.
//
// The inverse of NonTransferableAIDQB64, kept beside it so the two cannot drift.
// This is the whole reason a witness is named this way: given the identifier
// written in a key event, a verifier holds the key already and checks a receipt
// without asking anybody anything.
func KeyFromNonTransferableAID(aid string) ([]byte, error) {
	const code = "B"
	if len(aid) != 44 || aid[:1] != code {
		return nil, fmt.Errorf("%q is not a non-transferable identifier", aid)
	}
	// One code character, so one leading pad character to realign to base64.
	raw, err := base64.RawURLEncoding.DecodeString("A" + aid[1:])
	if err != nil {
		return nil, fmt.Errorf("identifier is not valid base64url: %w", err)
	}
	if len(raw) != 33 {
		return nil, fmt.Errorf("expected 32 key bytes, got %d", len(raw)-1)
	}
	return raw[1:], nil
}

// VerkeyQB64 encodes a raw Ed25519 public key as a CESR qb64 verfer (code "D"). Use this for
// keys passed to the KERI driver's inception endpoints: the driver's _extract_raw_key reads a
// leading "B"/"D" as a CESR code, so a raw base64 key that happens to start with B/D is
// misparsed. qb64 is unambiguous. Falls back to empty string only on an impossible encode error.
func VerkeyQB64(pub []byte) string {
	s, err := MatterFixedQB64("D", pub)
	if err != nil {
		return ""
	}
	return s
}
