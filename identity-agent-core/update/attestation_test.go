package update

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/zeebo/blake3"
)

func TestAttestationBlake3GateVerified(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "agent")
	payload := []byte("identity-agent-core-test-binary")
	if err := os.WriteFile(binPath, payload, 0755); err != nil {
		t.Fatal(err)
	}

	blake := blake3.Sum256(payload)
	sha := sha256.Sum256(payload)

	m := &Manifest{
		Components: map[string]ComponentEntry{
			"go_backend": {
				Version: "1.0.0",
				Artifacts: []Artifact{{
					Platform:   CurrentPlatform(),
					Blake3_256: hex.EncodeToString(blake[:]),
					SHA256:     hex.EncodeToString(sha[:]),
				}},
			},
		},
	}

	a := NewAttestation(binPath, CurrentPlatform())
	a.SetManifest(m)
	a.SetInstalledVersions(map[string]string{"go_backend": "1.0.0"})

	g := a.Genuineness()
	if g.Status != "verified" {
		t.Fatalf("expected verified, got %s (%s)", g.Status, g.Message)
	}
	if g.RunningBlake3_256 != g.ExpectedBlake3_256 {
		t.Fatalf("blake3 mismatch: %s vs %s", g.RunningBlake3_256, g.ExpectedBlake3_256)
	}
	if g.RunningSHA256 == "" || g.ExpectedSHA256 == "" {
		t.Fatal("expected interop sha256 fields populated")
	}
}

func TestAttestationBlake3GateMismatch(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "agent")
	if err := os.WriteFile(binPath, []byte("live-binary"), 0755); err != nil {
		t.Fatal(err)
	}

	m := &Manifest{
		Components: map[string]ComponentEntry{
			"go_backend": {
				Version: "1.0.0",
				Artifacts: []Artifact{{
					Platform:   CurrentPlatform(),
					Blake3_256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					SHA256:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				}},
			},
		},
	}

	a := NewAttestation(binPath, CurrentPlatform())
	a.SetManifest(m)
	g := a.Genuineness()
	if g.Status != "mismatch" {
		t.Fatalf("expected mismatch, got %s", g.Status)
	}
	if g.Message == "" {
		t.Fatal("expected mismatch message mentioning blake3_256")
	}
}

func TestCurrencyAxisWarnOnly(t *testing.T) {
	a := NewAttestation("", CurrentPlatform())
	a.SetInstalledVersions(map[string]string{"go_backend": "1.0.0"})
	a.SetManifest(&Manifest{
		Components: map[string]ComponentEntry{
			"go_backend": {Version: "2.0.0"},
		},
	})
	c := a.Currency()
	if c.Status != "outdated" {
		t.Fatalf("expected outdated, got %s", c.Status)
	}
}
