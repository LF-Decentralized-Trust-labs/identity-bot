package update

import "testing"

func TestResolveManifestURLDefault(t *testing.T) {
	t.Setenv("UPDATE_MANIFEST_URL", "")
	dir := t.TempDir()
	if got := ResolveManifestURL(dir); got != DefaultManifestURL {
		t.Fatalf("expected default %s, got %s", DefaultManifestURL, got)
	}
}

func TestResolveManifestURLEnvOverride(t *testing.T) {
	t.Setenv("UPDATE_MANIFEST_URL", "https://example.com/manifest.json")
	if got := ResolveManifestURL(t.TempDir()); got != "https://example.com/manifest.json" {
		t.Fatalf("unexpected url %s", got)
	}
}

func TestResolveManifestURLConfigFile(t *testing.T) {
	t.Setenv("UPDATE_MANIFEST_URL", "")
	dir := t.TempDir()
	if err := SaveConfigFile(dir, ConfigFile{ManifestURL: "https://config.example/manifest.json"}); err != nil {
		t.Fatal(err)
	}
	if got := ResolveManifestURL(dir); got != "https://config.example/manifest.json" {
		t.Fatalf("unexpected url %s", got)
	}
}

func TestDefaultConfigUsesOSSManifestURL(t *testing.T) {
	t.Setenv("UPDATE_MANIFEST_URL", "")
	cfg := DefaultConfig(t.TempDir())
	if cfg.ManifestURL != DefaultManifestURL {
		t.Fatalf("expected %s, got %s", DefaultManifestURL, cfg.ManifestURL)
	}
}