//go:build unix

package recovery

import (
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/backup"
)

// A symbolic link at the file's name is replaced, not written through: only a
// write that goes to a temporary beside it and renames it into place does
// that. A plain os.WriteFile follows the link and rewrites the victim, which
// is also what truncates a file in place and leaves it empty on a crash.
func plantALinkAt(t *testing.T, path string) (victim string) {
	t.Helper()
	victim = filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	return victim
}

func requireWrittenWhole(t *testing.T, path, victim, want string) {
	t.Helper()
	if b, _ := os.ReadFile(victim); string(b) != "untouched" {
		t.Fatalf("the file was written in place (through a link): victim now %q", b)
	}
	if b, _ := os.ReadFile(path); string(b) != want {
		t.Fatalf("read back %q, want %q", b, want)
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode().Perm() != 0o600 || !fi.Mode().IsRegular() {
		t.Fatalf("want a regular 0600 file, got %v (%v)", fi, err)
	}
}

func TestTheRestoredLoginRelationshipsAreWrittenWhole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "login_relationships.json")
	victim := plantALinkAt(t, path)
	svc := &Service{DataDir: dir}
	payload := &RestoredPayload{Bundle: &backup.PayloadBundle{
		Sections: map[string][]byte{"login_relationships": []byte(`{"a":1}`)}}}
	if err := svc.restoreTheKeyMaterial(payload); err != nil {
		t.Fatal(err)
	}
	requireWrittenWhole(t, path, victim, `{"a":1}`)
}

func TestTheDuressPolicyIsWrittenWhole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "duress_policy.json")
	victim := plantALinkAt(t, path)
	svc := NewService(dir, nil, nil)
	if err := svc.SaveDuressPolicy(DuressPolicy{Protection: DuressWait, WaitHours: 72}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "untouched" {
		t.Fatalf("the policy was written in place: victim now %q", b)
	}
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("want a regular 0600 file, got %v (%v)", fi, err)
	}
	if got := svc.LoadDuressPolicy(); got.Protection != DuressWait || got.WaitHours != 72 {
		t.Fatalf("policy did not survive: %+v", got)
	}
}

func TestTheUnpackedDatabaseIsWrittenWhole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.db")
	victim := plantALinkAt(t, path)
	if err := unpackTheDatabase(path, []byte("db bytes")); err != nil {
		t.Fatal(err)
	}
	requireWrittenWhole(t, path, victim, "db bytes")
}

func TestTheRunningRotationIsWrittenWhole(t *testing.T) {
	dir := t.TempDir()
	run := RunningRootAIDRotation{OldRootAID: "Eold", NewRootAID: "Enew"}
	path, err := rootAIDRunPath(dir, run.OldRootAID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	victim := plantALinkAt(t, path)
	if err := keepRunningRootAIDRotation(dir, run); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "untouched" {
		t.Fatalf("the running rotation was written in place: victim now %q", b)
	}
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("want a regular 0600 file, got %v (%v)", fi, err)
	}
	got, err := RunningRootAIDRotations(dir)
	if err != nil || len(got) != 1 || got[0].NewRootAID != "Enew" {
		t.Fatalf("run did not survive: %+v %v", got, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("left beside it: %v", entries)
	}
}
