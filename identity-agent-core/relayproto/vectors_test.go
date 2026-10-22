package relayproto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"os/exec"
	"testing"
)

// Every published vector is what CanonicalBody produces, and its signature is
// what the published key makes over those bytes. A change to the canonical
// form breaks this test before it breaks another implementation.
func TestThePublishedSigningVectorsHold(t *testing.T) {
	set, err := SigningVectors()
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Vectors) == 0 || len(set.Refused) == 0 {
		t.Fatal("the vector file is empty")
	}
	seed, err := hex.DecodeString(set.SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	if got := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)); got != set.PublicKey {
		t.Fatalf("public key %s, the file says %s", got, set.PublicKey)
	}
	for _, v := range set.Vectors {
		fields := map[string]any{}
		for k, s := range v.Fields {
			fields[k] = s
		}
		got, err := CanonicalBody(fields)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if string(got) != v.Canonical {
			t.Fatalf("%s:\n got  %s\n want %s", v.Name, got, v.Canonical)
		}
		if sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, got)); sig != v.Signature {
			t.Fatalf("%s: signature %s, the file says %s", v.Name, sig, v.Signature)
		}
	}
	for _, r := range set.Refused {
		if _, err := CanonicalBody(r.Fields); err == nil {
			t.Fatalf("%s was signed; it must be refused", r.Name)
		}
	}
}

// An implementation written from the ADR's text, in another language, agrees
// with the vector file. Skipped where Python is not installed.
func TestAnIndependentImplementationAgreesWithTheVectors(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	out, err := exec.Command(py, "check_signing_vectors.py", "signing-vectors.json").CombinedOutput()
	if err != nil {
		t.Fatalf("the independent check disagrees:\n%s", out)
	}
}
