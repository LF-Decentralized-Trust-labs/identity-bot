package atomicfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// A write replaces the file whole, with the mode asked for, and leaves
// nothing beside it.
func TestAWriteReplacesTheFileAndLeavesNothingBeside(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "record.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "new" {
		t.Fatalf("read back %q", b)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("left beside it: %v", entries)
	}
}

// A create never replaces what is there.
func TestACreateNeverReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := Create(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Create(path, []byte("second"), 0o600); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("%v, want it to exist already", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "first" {
		t.Fatalf("read back %q", b)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("left beside it: %v", entries)
	}
}

// A write into a directory that is not there fails, and makes nothing.
func TestAWriteThatCannotHappenSaysSo(t *testing.T) {
	if err := Write(filepath.Join(t.TempDir(), "missing", "record.json"), []byte("x"), 0o600); err == nil {
		t.Fatal("a write into a missing directory reported success")
	}
}

// A write stopped after its contents are on disk and before they take the
// target's name, as a crash would stop it, leaves no target and nothing
// beside it: never an empty or half-written file under the real name.
func TestAStoppedWriteLeavesNoPartialFile(t *testing.T) {
	stop := errors.New("stopped")
	beforePlacing = func() error { return stop }
	defer func() { beforePlacing = func() error { return nil } }()
	for _, write := range []func(string, []byte, fs.FileMode) error{Write, Create} {
		dir := t.TempDir()
		path := filepath.Join(dir, "owner_authority.json")
		if err := write(path, []byte(`{"aid":"E"}`), 0o600); !errors.Is(err, stop) {
			t.Fatalf("%v, want the stop", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("a stopped write left the target: %v", err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Fatalf("a stopped write left %v", entries)
		}
	}
}

// Only a temporary this package names is one: the target's name, ".tmp-"
// and digits.
func TestATemporaryIsRecognisedByItsWholeName(t *testing.T) {
	for name, want := range map[string]bool{
		"didcomm_keys.json.tmp-123456": true,
		"shares_held/E.json.tmp-9":     true,
		"notes.tmp-draft":              false,
		".tmp-123":                     false,
		"record.json.tmp-":             false,
		"record.json":                  false,
	} {
		if IsTemp(name) != want {
			t.Errorf("IsTemp(%q) = %v, want %v", name, !want, want)
		}
	}
}

// Leftovers are removed at every depth once they are old, and one that is
// fresh, which may be a write in flight, is not. Nothing else is touched.
func TestStaleTemporariesAreRemovedAndFreshOnesKept(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "shares_held")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	write := func(path string, mtime time.Time) {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	staleTop := filepath.Join(root, "didcomm_keys.json.tmp-1")
	staleSub := filepath.Join(sub, "E.json.tmp-2")
	fresh := filepath.Join(sub, "F.json.tmp-3")
	kept := filepath.Join(sub, "E.json")
	write(staleTop, old)
	write(staleSub, old)
	write(fresh, time.Now())
	write(kept, old)
	removed, err := RemoveStale(root, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 2 {
		t.Fatalf("removed %v, want the two stale temporaries", removed)
	}
	for _, p := range []string{staleTop, staleSub} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s was left", p)
		}
	}
	for _, p := range []string{fresh, kept} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s was removed: %v", p, err)
		}
	}
}
