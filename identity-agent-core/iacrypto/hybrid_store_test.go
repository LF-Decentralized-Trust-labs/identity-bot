package iacrypto_test

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"
	"identity-agent-core/iacrypto"
)

func fileStore(t *testing.T, dir string) *keri.FileKeyStore {
	t.Helper()
	s, err := keri.NewFileKeyStore(dir, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The whole loop: found an identity, persist it, lose the process, recover it,
// and sign something that verifies.
//
// Before this, a hybrid identity could be created and never used — its secrets
// existed only in the memory of whatever created them.
func TestAHybridIdentitySurvivesARestartAndCanStillSign(t *testing.T) {
	dir := t.TempDir()

	material, secrets, err := iacrypto.GenerateHybridKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	inception, err := iacrypto.BuildHybridInception(material)
	if err != nil {
		t.Fatal(err)
	}
	if err := iacrypto.StoreHybridSecrets(fileStore(t, dir), "alice", secrets); err != nil {
		t.Fatalf("the identity's secrets could not be stored: %v", err)
	}

	// A new process: nothing in memory, only what is on disk.
	recovered, err := iacrypto.LoadHybridSecrets(fileStore(t, dir), "alice")
	if err != nil {
		t.Fatalf("a stored hybrid identity could not be recovered: %v", err)
	}

	msg := []byte("something this identity is asserting after a restart")
	wire, err := iacrypto.SignHybrid(recovered, msg)
	if err != nil {
		t.Fatalf("the recovered identity could not sign: %v", err)
	}

	if !iacrypto.VerifyHybridSignature(msg, wire,
		material.Ed25519SigningRaw, material.MLDSA65SigningRaw, inception.InceptionEvent) {
		t.Error("a signature made by the recovered identity does not verify against the " +
			"inception event it was founded with")
	}
}

// Both halves must be real. A signature that verifies classically while the
// post-quantum half is nonsense is the exact failure the cipher suite exists to
// prevent, and it is invisible to a classical verifier.
func TestBothHalvesOfTheSignatureAreRequired(t *testing.T) {
	material, secrets, err := iacrypto.GenerateHybridKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	inception, err := iacrypto.BuildHybridInception(material)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("a message")
	wire, err := iacrypto.SignHybrid(secrets, msg)
	if err != nil {
		t.Fatal(err)
	}
	edVK, pqVK := material.Ed25519SigningRaw, material.MLDSA65SigningRaw
	if !iacrypto.VerifyHybridSignature(msg, wire, edVK, pqVK, inception.InceptionEvent) {
		t.Fatal("the honest signature does not verify, so the negative cases prove nothing")
	}

	// Corrupt one character deep inside the post-quantum half.
	broken := []byte(wire)
	i := len(broken) - 20
	if broken[i] == 'A' {
		broken[i] = 'B'
	} else {
		broken[i] = 'A'
	}
	if iacrypto.VerifyHybridSignature(msg, string(broken), edVK, pqVK, inception.InceptionEvent) {
		t.Error("a signature whose post-quantum half was altered still verified")
	}

	if iacrypto.VerifyHybridSignature([]byte("a different message"), wire, edVK, pqVK,
		inception.InceptionEvent) {
		t.Error("the signature verified over bytes it was not made over")
	}
}

// A partial identity must not be stored. The store refuses to overwrite, so a
// half-written identity cannot be completed on a second attempt.
func TestAPartialIdentityIsNotStored(t *testing.T) {
	dir := t.TempDir()
	_, secrets, err := iacrypto.GenerateHybridKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	secrets.NextMLDSA65Seed = nil // as if the caller had dropped one

	if err := iacrypto.StoreHybridSecrets(fileStore(t, dir), "bob", secrets); err == nil {
		t.Fatal("a hybrid identity missing a secret was stored")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("%d files were written despite the refusal; a partial identity is on "+
			"disk and cannot be completed", len(entries))
	}
}

// Losing the pre-rotation secrets must be reported for what it is.
func TestLosingTheNextKeysIsReportedAsUnrecoverable(t *testing.T) {
	dir := t.TempDir()
	_, secrets, err := iacrypto.GenerateHybridKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	store := fileStore(t, dir)
	if err := iacrypto.StoreHybridSecrets(store, "carol", secrets); err != nil {
		t.Fatal(err)
	}
	// Remove only the pre-rotation material, as a partial backup would.
	for _, e := range mustReadDir(t, dir) {
		if strings.Contains(decodeName(e), "/next/") {
			if err := os.Remove(dir + "/" + e); err != nil {
				t.Fatal(err)
			}
		}
	}
	_, err = iacrypto.LoadHybridSecrets(fileStore(t, dir), "carol")
	if err == nil {
		t.Fatal("an identity missing its pre-rotation secrets loaded cleanly")
	}
	if !strings.Contains(err.Error(), "never rotate") {
		t.Errorf("the failure does not say the identity can never rotate: %v", err)
	}
}

func mustReadDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// decodeName reverses the store's filename encoding so a test can find the
// pre-rotation files without guessing.
func decodeName(fileName string) string {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSuffix(fileName, ".key"))
	if err != nil {
		return ""
	}
	return string(raw)
}
