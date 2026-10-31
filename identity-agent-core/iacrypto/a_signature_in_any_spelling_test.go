package iacrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// randomSig is 64 random bytes whose padded standard base64 starts with
// prefix, so the forms a first-character guess gets wrong can be drawn.
func randomSig(t *testing.T, prefix string) []byte {
	t.Helper()
	for i := 0; i < 1_000_000; i++ {
		sig := make([]byte, sigBytes)
		rand.Read(sig)
		if strings.HasPrefix(base64.StdEncoding.EncodeToString(sig), prefix) {
			return sig
		}
	}
	t.Fatalf("no signature starting %q was drawn", prefix)
	return nil
}

// indexedQB64 spells sig with a one-character code and one character of
// index, as a published stream carries it.
func indexedQB64(code byte, index int, sig []byte) string {
	padded := append([]byte{0, 0}, sig...)
	s := base64.RawURLEncoding.EncodeToString(padded)
	return string(code) + string(b64Chars[index]) + s[2:]
}

// withLeadBits sets the four lead bits the third character carries, which a
// canonical encoder leaves zero.
func withLeadBits(qb64 string) string {
	i := strings.IndexByte(b64Chars, qb64[2])
	return qb64[:2] + string(b64Chars[i|0x10]) + qb64[3:]
}

// Every genuine spelling of a signature reads back as its bytes, including
// the raw ones that start the way qb64 does.
func TestEverySpellingOfASignatureReadsBack(t *testing.T) {
	for _, prefix := range []string{"", "A", "B", "0B"} {
		sig := randomSig(t, prefix)
		qb64, err := MatterFixedQB64("0B", sig)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := DecodeEd25519SignatureQB64(qb64); err != nil || !bytes.Equal(got, sig) {
			t.Fatalf("0B %s read as %x (%v)", qb64, got, err)
		}
		for _, enc := range base64Spellings {
			s := enc.EncodeToString(sig)
			got, _, indexed, err := DecodeEd25519Signature(s, true)
			if err != nil || indexed || !bytes.Equal(got, sig) {
				t.Fatalf("raw %s read as %x indexed=%v (%v)", s, got, indexed, err)
			}
		}
		for _, code := range []byte{'A', 'B'} {
			s := indexedQB64(code, 3, sig)
			c, index, got, err := DecodeIndexedEd25519SignatureQB64(s)
			if err != nil || c != code || index != 3 || !bytes.Equal(got, sig) {
				t.Fatalf("indexed %s read as %c %d %x (%v)", s, c, index, got, err)
			}
			if _, _, _, err := DecodeEd25519Signature(s, false); err == nil {
				t.Fatalf("indexed %s was read where indexed signatures are not", s)
			}
		}
	}
}

// No second spelling of a signature is read, so a signature has one string
// form in qb64: lead bits set, characters added, characters missing, padding,
// or a code that is not a signature's are all refused as qb64. Where raw
// base64 is read too, such a string is at most some other 64 bytes, which is
// a different signature and fails to verify, never this one spelled again.
func TestNoSecondSpellingOfASignatureIsRead(t *testing.T) {
	sig := randomSig(t, "")
	qb64, _ := MatterFixedQB64("0B", sig)
	indexed := indexedQB64('A', 0, sig)
	for name, s := range map[string]string{
		"0B, lead bits set":     withLeadBits(qb64),
		"0B, characters added":  qb64 + "AAAA",
		"0B, one added":         qb64 + "A",
		"0B, one missing":       qb64[:87],
		"0B, padded":            qb64[:86] + "==",
		"0B, standard alphabet": strings.NewReplacer("-", "+", "_", "/").Replace(qb64[:2]) + "+" + qb64[3:],
		"A, lead bits set":      withLeadBits(indexed),
		"another two-char code": "0C" + qb64[2:],
	} {
		if _, err := DecodeEd25519SignatureQB64(s); err == nil {
			t.Errorf("%s: read as an unindexed signature", name)
		}
		if got, _, _, err := DecodeEd25519Signature(s, true); err == nil && bytes.Equal(got, sig) {
			t.Errorf("%s: read as the same signature, a second spelling", name)
		}
	}
	if _, _, _, err := DecodeIndexedEd25519SignatureQB64(withLeadBits(indexed)); err == nil {
		t.Error("an indexed signature with its lead bits set was read")
	}
}
