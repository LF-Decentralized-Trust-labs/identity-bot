package secureenclave

import (
	"context"
	"testing"
)

// An Identity Agent that attested a chain with a sandbox_apps component in it
// reads "mismatch" once its build stops measuring that component, and reads
// "verified" after its first run, which re-attests (Start runs RunOnce first):
// the chain hash changes once, and nothing is left for a person to do.
func TestAnAttestationSignedWithSandboxAppsIsReplacedOnTheFirstRun(t *testing.T) {
	dir := t.TempDir()
	signer := NewSoftwareSigner(dir)

	withIt := NewRegistry()
	withIt.Register("go_backend", func() (string, error) { return "backend-hash", nil })
	withIt.Register("sandbox_apps", func() (string, error) { return "manifests-hash", nil })
	was := NewRunner(RunnerConfig{DataDir: dir, Signer: signer, Registry: withIt})
	if err := was.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	now := NewRegistry()
	now.Register("go_backend", func() (string, error) { return "backend-hash", nil })
	r := NewRunner(RunnerConfig{DataDir: dir, Signer: signer, Registry: now})
	r.Load()
	if got := r.Genuineness().Status; got != "mismatch" {
		t.Fatalf("before its first run the old attestation reads %q, want mismatch", got)
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.Genuineness().Status; got != "verified" {
		t.Fatalf("after its first run the attestation reads %q, want verified", got)
	}
}
