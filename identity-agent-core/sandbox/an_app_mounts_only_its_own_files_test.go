package sandbox

import (
	"path/filepath"
	"strings"
	"testing"
)

// An app's manifest cannot mount the data directory, which holds the keys and
// the local owner secret, or any other host path: only its own directory.
func TestAnAppMountsOnlyItsOwnDirectory(t *testing.T) {
	dataDir := t.TempDir()
	for _, refused := range []string{
		"{DATA_DIR}",
		"{DATA_DIR}/keystore",
		"/etc",
		"/",
		"{APP_DATA}/../../",
		"{APP_DATA}/../other-app",
	} {
		if p, err := resolveVolumeHostPath(dataDir, "notes", refused); err == nil {
			t.Errorf("%q was mounted as %s", refused, p)
		}
	}
	got, err := resolveVolumeHostPath(dataDir, "notes", "{APP_DATA}/cache")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dataDir, "sandbox-volumes", "notes", "cache")
	if abs, _ := filepath.Abs(want); got != abs {
		t.Fatalf("mounted %s, want %s", got, abs)
	}
	if _, err := resolveVolumeHostPath(dataDir, "../x", "{APP_DATA}"); err == nil {
		t.Error("an app id that climbs out of its directory was used")
	}
}

// A manifest naming anything but its own directory is refused before it is
// ever installed.
func TestAManifestMountingTheDataDirectoryIsRefused(t *testing.T) {
	for _, host := range []string{"{DATA_DIR}", "/home", "{APP_DATA}/../x"} {
		m := &AppManifest{ID: "notes", Name: "Notes", ExecutionType: "container",
			DisplayMethod: "webview", NetworkMode: "isolated",
			Container: &ContainerConfig{Image: "notes:1", Volumes: map[string]string{host: "/data"}}}
		err := m.Validate()
		if err == nil || !strings.Contains(err.Error(), "volume") {
			t.Errorf("%q: %v", host, err)
		}
	}
}

// The proxy's log and trace never record the local owner secret.
func TestTheProxyLogRedactsTheLocalOwnerSecret(t *testing.T) {
	h := map[string][]string{"X-Local-Owner-Secret": {"the-secret-0123456789abcdefghijkl"}}
	if got := flattenHeaders(h)["X-Local-Owner-Secret"]; got != "[REDACTED]" {
		t.Fatalf("logged as %q", got)
	}
}
