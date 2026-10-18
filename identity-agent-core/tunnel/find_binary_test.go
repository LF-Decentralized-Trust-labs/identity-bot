package tunnel

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A packaged desktop app spawns the agent with a minimal PATH that excludes the
// helper it bundled beside the executable. searchDirs must still offer that
// location — and offer PATH first, so an operator's chosen binary still wins.
func TestSearchDirsOrderAndMembership(t *testing.T) {
	dirs := searchDirs("/sbin:/usr/sbin", "/Apps/Example.app/Contents/Resources/backend/identity-agent-core")

	idx := map[string]int{}
	for i, d := range dirs {
		if _, seen := idx[d]; !seen {
			idx[d] = i
		}
	}
	for _, d := range []string{
		"/sbin", "/usr/sbin",
		"/Apps/Example.app/Contents/Resources/backend",
		"/Apps/Example.app/Contents/Resources/backend/bin",
		"/opt/homebrew/bin",
	} {
		if _, ok := idx[d]; !ok {
			t.Errorf("searchDirs missing %q; got %v", d, dirs)
		}
	}
	// PATH is searched before the bundled and common install dirs.
	if idx["/usr/sbin"] > idx["/Apps/Example.app/Contents/Resources/backend"] ||
		idx["/Apps/Example.app/Contents/Resources/backend/bin"] > idx["/opt/homebrew/bin"] {
		t.Errorf("order wrong: PATH must precede exe dir, exe dir must precede common dirs; got %v", dirs)
	}
}

func TestSearchDirsWithoutExe(t *testing.T) {
	dirs := searchDirs("/usr/bin", "")
	if len(dirs) == 0 || dirs[0] != "/usr/bin" {
		t.Fatalf("expected PATH first, got %v", dirs)
	}
}

// Exercises the real findIn: it returns a helper bundled beside the executable
// even when it is not on PATH, prefers an earlier dir, and ignores a directory
// that merely shares the helper's name.
func TestFindInFindsBundledAndSkipsDir(t *testing.T) {
	pathDir := t.TempDir()
	bundleDir := t.TempDir()

	// A directory named like the binary must not be mistaken for it.
	if err := os.Mkdir(filepath.Join(bundleDir, "cloudflared"), 0o755); err != nil {
		t.Fatal(err)
	}
	// ...but a real one in a bin/ beside it should be found.
	binDir := filepath.Join(bundleDir, "bin")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bundled := filepath.Join(binDir, "cloudflared")
	writeExe(t, bundled)

	// Not on PATH (pathDir has nothing): found in the bundled bin dir.
	got, err := findIn([]string{pathDir, bundleDir, binDir}, "cloudflared")
	if err != nil {
		t.Fatalf("findIn: %v", err)
	}
	if got != bundled {
		t.Fatalf("got %q want %q (the directory named cloudflared must be skipped)", got, bundled)
	}

	// An earlier dir wins over a later one.
	early := filepath.Join(pathDir, "cloudflared")
	writeExe(t, early)
	got, _ = findIn([]string{pathDir, binDir}, "cloudflared")
	if got != early {
		t.Fatalf("expected the earlier dir to win: got %q want %q", got, early)
	}

	if _, err := findIn([]string{t.TempDir()}, "cloudflared"); err == nil {
		t.Fatal("expected an error when the binary is absent")
	}
}

// binaryNames adds the .exe form on Windows so a bundled cloudflared.exe matches.
func TestBinaryNames(t *testing.T) {
	names := binaryNames("cloudflared")
	if runtime.GOOS == "windows" {
		if len(names) != 2 || names[0] != "cloudflared.exe" {
			t.Fatalf("windows: want [cloudflared.exe cloudflared], got %v", names)
		}
	} else {
		if len(names) != 1 || names[0] != "cloudflared" {
			t.Fatalf("posix: want [cloudflared], got %v", names)
		}
	}
	// An explicit .exe is not doubled.
	if n := binaryNames("x.exe"); len(n) != 1 {
		t.Fatalf("an explicit .exe should not be re-suffixed, got %v", n)
	}
}

func writeExe(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}
