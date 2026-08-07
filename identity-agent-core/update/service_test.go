package update

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"
)

func TestServiceIngestAndStatus(t *testing.T) {
	dir := t.TempDir()
	ta, priv, _ := TestTrustAnchor()
	svc, err := NewService(Config{
		DataDir:     dir,
		ManifestURL: "http://127.0.0.1:9/manifest.json",
		TrustAnchor: ta,
		Installed:   map[string]string{"go_backend": "2.3.0"},
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	signed := mustSignTestManifest(t, priv)
	if err := svc.IngestManifest(signed); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	st := svc.Status()
	if !st.ManifestPresent {
		t.Fatal("expected manifest present")
	}
	if len(st.Available) == 0 {
		t.Fatal("expected available update")
	}
	if st.Settings.AutoApplyCritical != true {
		t.Fatal("auto_apply_critical should default ON")
	}
}

func TestServiceSettingsPersist(t *testing.T) {
	dir := t.TempDir()
	ta, _, _ := TestTrustAnchor()
	svc, _ := NewService(Config{DataDir: dir, TrustAnchor: ta})
	svc.UpdateSettings(Settings{AutoApplyCritical: false, Channel: "beta"})
	svc2, _ := NewService(Config{DataDir: dir, TrustAnchor: ta})
	if svc2.GetSettings().AutoApplyCritical {
		t.Fatal("expected persisted opt-out")
	}
	if svc2.GetSettings().Channel != "beta" {
		t.Fatal("expected beta channel")
	}
}

func TestCanDirectUpgrade(t *testing.T) {
	if !CanDirectUpgrade("2.3.0", "2.2.0", "2.4.0") {
		t.Fatal("expected direct upgrade allowed")
	}
	if CanDirectUpgrade("2.1.0", "2.2.0", "2.4.0") {
		t.Fatal("expected below_minimum_version")
	}
}

func mustSignTestManifest(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	unsigned := []byte(`{
  "manifest_version": 1,
  "published_at": "2026-06-15T00:00:00Z",
  "signing_key_id": "grape-release-test",
  "channels": {"stable": {"min_supported_manifest_version": 1}},
  "components": {
    "go_backend": {
      "version": "2.4.0",
      "minimum_version": "2.2.0",
      "critical": false,
      "artifacts": [{
        "platform": "` + CurrentPlatform() + `",
        "url": "https://example.com/artifact",
        "blake3_256": "0000000000000000000000000000000000000000000000000000000000000000",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "size_bytes": 0
      }]
    }
  },
  "compatibility": {},
  "changelog": [],
  "signature": ""
}`)
	signed, err := SignManifestForTest(unsigned, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func TestPollerStartStop(t *testing.T) {
	p := NewPoller("http://127.0.0.1:9/manifest.json")
	p.SetInterval(10 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)
	time.Sleep(30 * time.Millisecond)
	p.Stop()
}

func TestAttestationUnknownWithoutManifest(t *testing.T) {
	a := NewAttestation(filepath.Join(t.TempDir(), "missing"), CurrentPlatform())
	g := a.Genuineness()
	if g.Status != "unknown" {
		t.Fatalf("expected unknown, got %s", g.Status)
	}
}