package login

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// canonicalVerkey mirrors what AgentKeyPair.publicKeyEncoded produces for a
// one-character CESR code: prepend one pad byte, base64url the 33 bytes, and let
// the code replace the leading output character.
func canonicalVerkey(code string, raw []byte) string {
	padded := append([]byte{0}, raw...)
	return code + base64.RawURLEncoding.EncodeToString(padded)[1:]
}

func TestDecodeVerkeyCanonicalRoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Both the transferable "D" code and the non-transferable "B" (Ed25519N) code
	// carry the same 32 raw bytes and must decode back to them. "B" is the one
	// this change adds; "D" guards against breaking the branch that already worked.
	for _, code := range []string{"B", "D"} {
		qb64 := canonicalVerkey(code, pub)
		if len(qb64) != 44 {
			t.Fatalf("%s-code verkey length %d, want 44", code, len(qb64))
		}
		got, err := DecodeVerkey(qb64)
		if err != nil {
			t.Fatalf("DecodeVerkey(%s-code): %v", code, err)
		}
		if !bytes.Equal(got, pub) {
			t.Fatalf("%s-code verkey did not round-trip to the key it names", code)
		}
	}
}

func TestDecodeVerkeyNaiveBFormIsNotTheKey(t *testing.T) {
	// The pre-fix mobile encoding: 'B' + base64url(raw) with no pad byte. It is a
	// 44-char "B" string, so it reaches the same branch — and it must NOT come
	// back as the original key. Decoding it to the right bytes would mean the old
	// and new encodings were interchangeable, which is exactly the silent wrong
	// answer the canonical encoding fixed.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	naive := "B" + base64.RawURLEncoding.EncodeToString(pub)
	if len(naive) != 44 {
		t.Fatalf("naive form length %d, want 44", len(naive))
	}
	got, derr := DecodeVerkey(naive)
	if derr == nil && bytes.Equal(got, pub) {
		t.Fatal("the naive 'B'+base64 form decoded back to the signing key; " +
			"the two encodings are not distinguishable, so the fix is moot")
	}
}

// A raw key reaches here in every base64 spelling, padded URL-safe included,
// and one that happens to start with a qb64 code is still read as raw: qb64
// is never padded, so the padded spellings cannot be qb64.
func TestDecodeVerkeyReadsEveryBase64Spelling(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString("B/awzunMRvtYlgq21ZegG9MD5kNmLbPNspHGcryAbK4=")
	if err != nil {
		t.Fatal(err)
	}
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding,
	} {
		got, err := DecodeVerkey(enc.EncodeToString(raw))
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("%s read as %x (%v)", enc.EncodeToString(raw), got, err)
		}
	}
}
