package secureenclave

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The stored attestation's key and signature are read in their one canonical
// string. Read leniently, a signature with its spare bits set, or either value
// with a line break inside it, verified as the original.
func TestARespelledStoredAttestationIsNotVerified(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for name, mutate := range map[string]func(r *AttestationRecord){
		"signature spare bits": func(r *AttestationRecord) {
			last := len(r.Signature) - 1
			v := strings.IndexByte(alphabet, r.Signature[last])
			r.Signature = r.Signature[:last] + string(alphabet[v|1])
		},
		"signature line break": func(r *AttestationRecord) { r.Signature = r.Signature[:10] + "\n" + r.Signature[10:] },
		"key line break":       func(r *AttestationRecord) { r.PublicKey = r.PublicKey[:10] + "\n" + r.PublicKey[10:] },
		"key spare bits": func(r *AttestationRecord) {
			last := len(r.PublicKey) - 1
			v := strings.IndexByte(alphabet, r.PublicKey[last])
			r.PublicKey = r.PublicKey[:last] + string(alphabet[v|1])
		},
	} {
		dir := t.TempDir()
		binPath := filepath.Join(dir, "agent")
		if err := os.WriteFile(binPath, []byte("spelling-binary"), 0755); err != nil {
			t.Fatal(err)
		}
		reg := NewRegistry()
		reg.Register("go_backend", fileHasher(binPath))
		runner := NewRunner(RunnerConfig{DataDir: dir, Signer: newSoftwareSigner(dir), Registry: reg})
		if err := runner.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		if g := runner.Genuineness(); g.Status != "verified" {
			t.Fatalf("%s: the canonical record was not verified: %s", name, g.Message)
		}
		runner.mu.Lock()
		mutate(runner.record)
		runner.mu.Unlock()
		if g := runner.Genuineness(); g.Status == "verified" {
			t.Errorf("%s: the respelled record was verified", name)
		}
	}
}
