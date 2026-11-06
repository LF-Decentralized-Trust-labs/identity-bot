//go:build kerigo_pqtest

package iacrypto_test

import (
	"testing"

	"identity-agent-core/iacrypto"
)

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
