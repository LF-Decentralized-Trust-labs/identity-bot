package atomicfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
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
