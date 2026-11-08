package witnessproto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestTheSignedDigestStatementIsTheSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("kel-digest-statement-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct {
		Name      string  `json:"name"`
		AID       string  `json:"aid"`
		Seq       int     `json:"seq"`
		Digest    *string `json:"digest"`
		FirstSeen *string `json:"first_seen_at"`
		Observed  *string `json:"observed_since"`
		Statement string  `json:"statement"`
	}
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 2 {
		t.Fatal("the vectors have lost cases")
	}
	for _, v := range vs {
		got, err := DigestStatement(v.AID, v.Seq, v.Digest, v.FirstSeen, v.Observed)
		if err != nil || got != v.Statement {
			t.Errorf("%s: got %q, %v; the vectors say %q", v.Name, got, err, v.Statement)
		}
	}
}

// Two different answers must never share a statement.
func TestAFieldThatCouldBlurTwoAnswersIsRefused(t *testing.T) {
	d := "ab"
	for _, aid := range []string{"", "-", "E\naid=x", "E\x00"} {
		if _, err := DigestStatement(aid, 1, &d, nil, nil); err == nil {
			t.Errorf("aid %q was signable", aid)
		}
	}
	bad := "x\ndigest=y"
	if _, err := DigestStatement("E", 1, &bad, nil, nil); err == nil {
		t.Error("a digest with a line break was signable")
	}
	empty := ""
	if _, err := DigestStatement("E", 1, &empty, nil, nil); err == nil {
		t.Error("an empty digest was signable instead of absent")
	}
	if _, err := DigestStatement("E", -1, nil, nil, nil); err == nil {
		t.Error("a negative sequence was signable")
	}
	a, _ := DigestStatement("E", 1, nil, nil, nil)
	if !strings.HasPrefix(a, DigestStatementTag+"\n") {
		t.Error("the statement does not open with its tag")
	}
}

// A second implementation can check its signature, not only its text: every
// vector carries the signer (a non-transferable identifier, so itself the
// key) and its Ed25519 signature over the statement. The key is a test key
// (seed 0x01..0x20) and must never be trusted anywhere.
func TestTheSharedVectorsCarrySignaturesThatVerify(t *testing.T) {
	raw, err := os.ReadFile("kel-digest-statement-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct {
		Name      string `json:"name"`
		SignedBy  string `json:"signed_by"`
		Signature string `json:"signature"`
		Statement string `json:"statement"`
	}
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		// Both are CESR qb64: decode the whole text, then drop the bytes that
		// carry the code (one for the 44-character key "B...", two for the
		// 88-character signature "0B...").
		kb, err := base64.RawURLEncoding.DecodeString(v.SignedBy)
		if err != nil || len(kb) != 33 || v.SignedBy[0] != 'B' {
			t.Fatalf("%s: signed_by %q is not a key: %v", v.Name, v.SignedBy, err)
		}
		pub := kb[1:]
		if len(pub) != ed25519.PublicKeySize {
			t.Fatalf("%s: signed_by %q is not a key: %v", v.Name, v.SignedBy, err)
		}
		sigBytes, err := base64.RawURLEncoding.DecodeString(v.Signature)
		if err != nil || len(sigBytes) != 66 || !strings.HasPrefix(v.Signature, "0B") {
			t.Fatalf("%s: signature %q is not a 0B signature: %v", v.Name, v.Signature, err)
		}
		if !ed25519.Verify(pub, []byte(v.Statement), sigBytes[2:]) {
			t.Errorf("%s: the signature does not verify over the statement", v.Name)
		}
		if ed25519.Verify(pub, []byte(v.Statement+" "), sigBytes[2:]) {
			t.Errorf("%s: the signature verifies over altered text", v.Name)
		}
	}
}
