package vault

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func failWrites(t *testing.T) {
	t.Helper()
	orig := writeVaultFile
	writeVaultFile = func(string, []byte, fs.FileMode) error { return errors.New("disk full") }
	t.Cleanup(func() { writeVaultFile = orig })
}

// A write that stops before the new vault takes its name leaves the old vault
// whole and readable, and an abandoned temporary beside it does not matter.
func TestInterruptedWriteLeavesOldVaultReadable(t *testing.T) {
	dir := t.TempDir()
	cv := newTestVault(t, dir)
	if err := cv.SetKept(KeptRef("github-app"), "app", map[string]string{"k": "old"}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, vaultFileName))

	// A crash mid-write leaves a partial temporary, never a partial vault.
	if err := os.WriteFile(filepath.Join(dir, vaultFileName+".tmp-123"), []byte(`{"version":1,"nonce":"`), 0600); err != nil {
		t.Fatal(err)
	}
	failWrites(t)
	if err := cv.SetKept(KeptRef("github-app"), "app", map[string]string{"k": "new"}); err == nil {
		t.Fatal("expected the write to fail")
	}
	after, _ := os.ReadFile(filepath.Join(dir, vaultFileName))
	if string(before) != string(after) {
		t.Fatal("vault file changed by a failed write")
	}
	fresh := newTestVault(t, dir)
	var got map[string]string
	ok, err := fresh.Kept(KeptRef("github-app"), "app", &got)
	if err != nil || !ok || got["k"] != "old" {
		t.Fatalf("old vault not readable: ok=%v err=%v got=%v", ok, err, got)
	}
}

// Memory follows the disk: when the write fails the change is not kept in
// memory, so a retry really performs it instead of finding it already done.
func TestFailedWriteDoesNotChangeMemory(t *testing.T) {
	dir := t.TempDir()
	cv := newTestVault(t, dir)
	ref := KeptRef("github-app")
	if err := cv.SetKept(ref, "app", map[string]string{"k": "secret"}); err != nil {
		t.Fatal(err)
	}
	if err := cv.SetCredential("svc", []string{"a.example"}, map[string]string{"Authorization": "Bearer x"}); err != nil {
		t.Fatal(err)
	}

	orig := writeVaultFile
	failWrites(t)
	if err := cv.SetKept(ref, "app", map[string]string{"k": "withdrawn"}); err == nil {
		t.Fatal("expected failure")
	}
	if err := cv.RemoveKept(ref); err == nil {
		t.Fatal("expected failure")
	}
	if err := cv.RemoveCredential("svc"); err == nil {
		t.Fatal("expected failure")
	}
	if err := cv.SetCredential("svc", []string{"b.example"}, map[string]string{"Authorization": "Bearer y"}); err == nil {
		t.Fatal("expected failure")
	}
	if err := cv.SetBrainSignIn(BrainSignInRef("a1"), []byte(`{"x":1}`)); err == nil {
		t.Fatal("expected failure")
	}

	var got map[string]string
	if ok, _ := cv.Kept(ref, "app", &got); !ok || got["k"] != "secret" {
		t.Fatalf("memory changed by failed write: %v", got)
	}
	if !cv.HasService("svc") || cv.GetAPIKey("svc") != "x" {
		t.Fatal("service credential changed by failed write")
	}
	if cv.HasService(BrainSignInRef("a1")) {
		t.Fatal("failed brain sign-in write left an entry in memory")
	}

	// The retry, with the disk working again, really withdraws.
	writeVaultFile = orig
	if err := cv.SetKept(ref, "app", map[string]string{"k": "withdrawn"}); err != nil {
		t.Fatal(err)
	}
	fresh := newTestVault(t, dir)
	got = nil
	if ok, _ := fresh.Kept(ref, "app", &got); !ok || got["k"] != "withdrawn" {
		t.Fatalf("retry did not reach disk: %v", got)
	}
	if err := cv.RemoveKept(ref); err != nil {
		t.Fatal(err)
	}
	if ok, _ := newTestVault(t, dir).Kept(ref, "app", &got); ok {
		t.Fatal("removed entry still on disk")
	}
}

func TestVaultWriteLeavesNoTemporaryAndKeepsMode(t *testing.T) {
	dir := t.TempDir()
	cv := newTestVault(t, dir)
	if err := cv.SetCredential("svc", []string{"a.example"}, map[string]string{"Authorization": "Bearer x"}); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temporary left behind: %s", e.Name())
		}
	}
	if fi, err := os.Stat(filepath.Join(dir, vaultFileName)); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("mode: %v %v", fi, err)
	}
}
