package sandbox

import (
	"os"
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
	want, _ := filepath.EvalSymlinks(filepath.Join(dataDir, "sandbox-volumes", "notes", "cache"))
	if got != want {
		t.Fatalf("mounted %s, want %s", got, want)
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

// An app writes into what it mounts. A link it plants there, pointing at the
// data directory, must not turn a later mount of that link into the data
// directory itself.
func TestALinkAnAppPlantedCannotBeMounted(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := resolveVolumeHostPath(dataDir, "notes", "{APP_DATA}"); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dataDir, "sandbox-volumes", "notes", "link")
	if err := os.Symlink(dataDir, link); err != nil {
		t.Skip("cannot make a link here:", err)
	}
	for _, host := range []string{"{APP_DATA}/link", "{APP_DATA}/link/keystore"} {
		if p, err := resolveVolumeHostPath(dataDir, "notes", host); err == nil {
			t.Errorf("%q through a planted link was mounted as %s", host, p)
		}
	}
	// A link replacing the app's own directory is refused the same way.
	os.RemoveAll(filepath.Join(dataDir, "sandbox-volumes", "other"))
	if err := os.Symlink(dataDir, filepath.Join(dataDir, "sandbox-volumes", "other")); err != nil {
		t.Fatal(err)
	}
	if p, err := resolveVolumeHostPath(dataDir, "other", "{APP_DATA}"); err == nil {
		t.Errorf("an app directory that is a link was mounted as %s", p)
	}
}
