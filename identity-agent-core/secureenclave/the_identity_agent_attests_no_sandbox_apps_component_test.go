package secureenclave

import (
	"os"
	"path/filepath"
	"testing"
)

// The Identity Agent starts no container or program of its own, so the signed
// attestation's component chain names no sandbox-apps component and does not
// move when a manifests directory beside the data directory changes.
func TestTheIdentityAgentAttestsNoSandboxAppsComponent(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range DefaultRegistry(data).Names() {
		if name == "sandbox_apps" {
			t.Fatal("the default component chain still names sandbox_apps")
		}
	}

	hashOf := func() string {
		h, _, err := DefaultRegistry(data).ChainHash()
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	before := hashOf()
	manifests := filepath.Join(root, "manifests")
	if err := os.MkdirAll(manifests, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manifests, "x.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if hashOf() != before {
		t.Fatal("the attested chain changed when a manifests directory changed")
	}
}
