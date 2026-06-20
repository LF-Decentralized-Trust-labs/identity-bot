package m63

import (
	"encoding/base64"
	"fmt"
)

const (
	CipherSuiteIAHybrid1   = "IA-HYBRID-1"
	CESRMLDSA65Verkey      = "1PDA"
	CESRMLDSA65Sig         = "1PDS"
	CESRMLKEM768Encap      = "1PKM"
	CESRX25519Pubkey       = "1PXB"
	MLDSA65VerkeyBytes     = 1952
	MLDSA65SigBytes        = 3309
	MLKEM768EncapBytes     = 1184
	X25519PubkeyBytes      = 32
	Ed25519PubkeyBytes     = 32
	Ed25519SigBytes        = 64
	CtrControllerIdxSigs   = "-A"
	C2Message              = "m63-c2-hybrid-signature-golden-vector"
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