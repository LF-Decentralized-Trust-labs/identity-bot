package keriengine

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// A raw key in padded base64 is 44 characters, like a qb64 key, and one in
// 32 starts with D or B, like a qb64 key's derivation code. These are such
// keys. Each was refused as "a qb64 key that does not decode", one of them in
// a test run, so creating, rotating or verifying with a genuine key failed at
// random. Padding and the alphabet tell the two apart.
func TestARawKeyIsNeverTakenForQB64(t *testing.T) {
	for _, raw64 := range []string{
		"B/awzunMRvtYlgq21ZegG9MD5kNmLbPNspHGcryAbK4=", // standard alphabet
		"DhIl/3hQFnLNtcKl1Jf8wdRBd5k81l/tS4158ZPje64=",
		"DsOf06GmmgHo7sSLghlyd5EbCB9AhW146xyb1vFdeiI=", // only the padding is not base64url
	} {
		raw, err := base64.StdEncoding.DecodeString(raw64)
		if err != nil {
			t.Fatal(err)
		}
		want, err := keri.MatterQB64(keri.CodeEd25519, raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, spelling := range []string{raw64, base64.URLEncoding.EncodeToString(raw)} {
			got, err := normaliseKey(spelling, true)
			if err != nil {
				t.Fatalf("%s was refused: %v", spelling, err)
			}
			if got != want {
				t.Fatalf("%s read as %s, want %s", spelling, got, want)
			}
		}
		// The same key already in qb64 is taken as it is.
		if got, err := normaliseKey(want, true); err != nil || got != want {
			t.Fatalf("qb64 %s read as %s (%v)", want, got, err)
		}
	}
}

// The engine reads raw keys in base64 only, as it always has: hex is refused.
func TestTheEngineDoesNotReadAKeyInHex(t *testing.T) {
	raw, _ := base64.StdEncoding.DecodeString("DDfja0BSaHyUzcmR5qSWupbddyc85Oe3PRRcFkiitao=")
	if _, err := normaliseKey(hex.EncodeToString(raw), true); err == nil {
		t.Fatal("a key in hex was read")
	}
}
