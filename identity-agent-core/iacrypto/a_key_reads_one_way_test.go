package iacrypto

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// A raw key in standard base64 is 44 characters ending in "=", and a qb64 key
// is 44 characters of base64url that never does, so no value is both. The
// first letter must never decide: about 1 raw key in 32 starts with D or B,
// and those that also contain + or / once were refused as bad qb64
// ('"D" value is not valid base64url').

// spellings returns every way a raw key is written that this core reads.
func spellings(raw []byte) map[string]string {
	return map[string]string{
		"qb64-D":     VerkeyQB64(raw),
		"qb64-B":     NonTransferableAIDQB64(raw),
		"std-padded": base64.StdEncoding.EncodeToString(raw),
		"std-raw":    base64.RawStdEncoding.EncodeToString(raw),
		"url-padded": base64.URLEncoding.EncodeToString(raw),
		"url-raw":    base64.RawURLEncoding.EncodeToString(raw),
	}
}

func TestAStandardBase64KeyStartingWithDOrBAndHoldingPlusOrSlashIsRead(t *testing.T) {
	found := map[byte]int{}
	for i := 0; i < 200000 && (found['D'] < 5 || found['B'] < 5); i++ {
		raw := randomKey(t)
		s := base64.StdEncoding.EncodeToString(raw)
		if (s[0] != 'D' && s[0] != 'B') || !bytes.ContainsAny([]byte(s), "+/") {
			continue
		}
		found[s[0]]++
		got, code, err := DecodeEd25519Key(s, false)
		if err != nil {
			t.Fatalf("raw key %s was refused: %v", s, err)
		}
		if code != "" || !bytes.Equal(got, raw) {
			t.Fatalf("raw key %s read as code %q, bytes %x; want raw %x", s, code, got, raw)
		}
		if c, ok := Ed25519KeyCode(s); ok {
			t.Fatalf("raw key %s taken for qb64 code %s", s, c)
		}
	}
	if found['D'] < 5 || found['B'] < 5 {
		t.Fatalf("did not generate enough keys of the failing class: %v", found)
	}
}

func TestEveryRandomKeyReadsTheSameInEverySpelling(t *testing.T) {
	for i := 0; i < 3000; i++ {
		raw := randomKey(t)
		for name, s := range spellings(raw) {
			got, code, err := DecodeEd25519Key(s, false)
			if err != nil {
				t.Fatalf("%s %q refused: %v", name, s, err)
			}
			if !bytes.Equal(got, raw) {
				t.Fatalf("%s %q read as %x, want %x", name, s, got, raw)
			}
			wantQB64 := name == "qb64-D" || name == "qb64-B"
			if (code != "") != wantQB64 {
				t.Fatalf("%s %q: code %q", name, s, code)
			}
		}
	}
}
