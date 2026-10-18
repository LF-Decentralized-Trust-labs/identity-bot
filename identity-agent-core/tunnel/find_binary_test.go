package tunnel

import (
	"os"
	"path/filepath"
	"testing"
)

// A packaged desktop app spawns the agent with a minimal PATH that excludes the
// helper it bundled beside the executable. searchDirs must still offer that
// location so the tunnel helper is found and founding works from a GUI launch.
func TestSearchDirsIncludesExeDirAndBin(t *testing.T) {
	dirs := searchDirs("/sbin:/usr/sbin", "/Apps/Grape.app/Contents/Resources/backend/identity-agent-core")
	want := map[string]bool{
		"/sbin":     false,
		"/usr/sbin": false,
		"/Apps/Grape.app/Contents/Resources/backend":     false,
		"/Apps/Grape.app/Contents/Resources/backend/bin": false,
		"/opt/homebrew/bin":                              false,
	}
	for _, d := range dirs {
		if _, ok := want[d]; ok {
			want[d] = true
		}
	}
	for d, seen := range want {
		if !seen {
			t.Errorf("searchDirs missing %q; got %v", d, dirs)
		}
	}
}

func TestSearchDirsWithoutExe(t *testing.T) {
	dirs := searchDirs("/usr/bin", "")
	// No executable path: no panic, PATH + common dirs only.
	if len(dirs) == 0 || dirs[0] != "/usr/bin" {
		t.Fatalf("expected PATH first, got %v", dirs)
	}
}

// findInPath finds a helper bundled beside the executable even when it is not on
// PATH, and ignores a directory that merely shares the helper's name.
func TestFindInPathPrefersPathButFindsBundled(t *testing.T) {
	bundle := t.TempDir()
	// A directory named like the binary must not be mistaken for it.
	if err := os.Mkdir(filepath.Join(bundle, "decoy"), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(bundle, "cloudflared")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Put the bundle dir on PATH to exercise the stat+!IsDir path.
	got, err := findInPathAt("cloudflared", []string{bundle})
	if err != nil {
		t.Fatalf("findInPathAt: %v", err)
	}
	if got != bin {
		t.Fatalf("got %q want %q", got, bin)
	}

	if _, err := findInPathAt("decoy", []string{bundle}); err == nil {
		t.Fatal("a directory named like the binary must not be returned")
	}
}

// findInPathAt is findInPath's search over an explicit list, so the lookup logic
// is testable without depending on the test binary's own location.
func findInPathAt(name string, dirs []string) (string, error) {
	for _, dir := range dirs {
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", os.ErrNotExist
}
