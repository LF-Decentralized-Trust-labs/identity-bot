package secureenclave

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"identity-agent-core/update"
)

func TestRunnerSelfAttestation(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "agent")
	if err := os.WriteFile(binPath, []byte("runner-test-binary"), 0755); err != nil {
		t.Fatal(err)
	}

	reg := NewRegistry()
	reg.Register("go_backend", fileHasher(binPath))

	runner := NewRunner(RunnerConfig{
		DataDir:  dir,
		Signer:   newSoftwareSigner(dir),
		Registry: reg,
	})
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("run once: %v", err)
	}

	f := runner.Freshness()
	if f.Status != "fresh" {
		t.Fatalf("expected fresh, got %s (%s)", f.Status, f.Message)
	}
	g := runner.Genuineness()
	if g.Status != "verified" {
		t.Fatalf("expected verified, got %s (%s)", g.Status, g.Message)
	}
}

func TestTrustGateBlocksStaleAttestation(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "agent")
	if err := os.WriteFile(binPath, []byte("trust-gate-binary"), 0755); err != nil {
		t.Fatal(err)
	}

	reg := NewRegistry()
	reg.Register("go_backend", fileHasher(binPath))
	runner := NewRunner(RunnerConfig{
		DataDir:  dir,
		Signer:   newSoftwareSigner(dir),
		Registry: reg,
	})
	t.Setenv("ATTESTATION_CADENCE_HOURS", "1")
	runner.cadence = time.Hour

	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	runner.record.SignedAt = time.Now().UTC().Add(-2 * time.Hour)
	runner.mu.Unlock()

	att := update.NewAttestation(binPath, update.CurrentPlatform())
	gate := NewTrustGate(runner, att)
	if gate.AllowsTrustOperations() {
		t.Fatal("expected stale attestation to block trust")
	}
	if reason := gate.TrustBlockedReason(); reason == "" {
		t.Fatal("expected blocked reason")
	}
}

func TestTrustGateCurrencyWarnOnly(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "agent")
	if err := os.WriteFile(binPath, []byte("currency-binary"), 0755); err != nil {
		t.Fatal(err)
	}

	reg := NewRegistry()
	reg.Register("go_backend", fileHasher(binPath))
	runner := NewRunner(RunnerConfig{
		DataDir:  dir,
		Signer:   newSoftwareSigner(dir),
		Registry: reg,
	})
	_ = runner.RunOnce(context.Background())

	att := update.NewAttestation(binPath, update.CurrentPlatform())
	att.SetInstalledVersions(map[string]string{"go_backend": "1.0.0"})
	att.SetManifest(&update.Manifest{
		Components: map[string]update.ComponentEntry{
			"go_backend": {Version: "2.0.0"},
		},
	})

	gate := NewTrustGate(runner, att)
	if warn := gate.CurrencyWarning(); warn == "" {
		t.Fatal("expected currency warning")
	}
	if !gate.AllowsTrustOperations() {
		t.Fatalf("currency warning must not block trust, reason=%s", gate.TrustBlockedReason())
	}
}
