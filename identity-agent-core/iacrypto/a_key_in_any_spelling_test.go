package iacrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// No raw key, in any base64 spelling, is ever taken for qb64, and every qb64
// key is. One in 32 padded raw keys starts with D or B, so thousands are drawn.
func TestARawKeyIsNeverTakenForQB64InAnySpelling(t *testing.T) {
	for i := 0; i < 5000; i++ {
		raw := make([]byte, Ed25519PubkeyBytes)
		rand.Read(raw)
		for _, enc := range base64Spellings {
			s := enc.EncodeToString(raw)
			if _, ok := Ed25519KeyCode(s); ok {
				t.Fatalf("raw key %s was taken for qb64", s)
			}
			got, code, err := DecodeEd25519Key(s, false)
			if err != nil || code != "" || !bytes.Equal(got, raw) {
				t.Fatalf("%s read as %x code %q (%v)", s, got, code, err)
			}
		}
		for _, qb64 := range []string{VerkeyQB64(raw), NonTransferableAIDQB64(raw)} {
			got, code, err := DecodeEd25519Key(qb64, false)
			if err != nil || code != qb64[:1] || !bytes.Equal(got, raw) {
				t.Fatalf("qb64 %s read as %x code %q (%v)", qb64, got, code, err)
			}
		}
	}
}

// Hex is read only where a caller asks for it.
func TestHexIsReadOnlyWhenAsked(t *testing.T) {
	raw := make([]byte, Ed25519PubkeyBytes)
	rand.Read(raw)
	h := hex.EncodeToString(raw)
	if _, _, err := DecodeEd25519Key(h, false); err == nil {
		t.Fatal("hex was read where it was not asked for")
	}
	if got, _, err := DecodeEd25519Key(h, true); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("hex read as %x (%v)", got, err)
	}
}

// A value of the wrong size is refused rather than truncated or padded.
func TestDecodeSizedRefusesTheWrongSize(t *testing.T) {
	sig := make([]byte, ed25519.SignatureSize)
	rand.Read(sig)
	for _, enc := range base64Spellings {
		if got, err := DecodeSized(enc.EncodeToString(sig), ed25519.SignatureSize, false); err != nil || !bytes.Equal(got, sig) {
			t.Fatalf("a signature in %v read as %x (%v)", enc, got, err)
		}
	}
	if _, err := DecodeSized(base64.StdEncoding.EncodeToString(sig[:63]), ed25519.SignatureSize, true); err == nil {
		t.Fatal("63 bytes were taken for a 64-byte signature")
	}
}
