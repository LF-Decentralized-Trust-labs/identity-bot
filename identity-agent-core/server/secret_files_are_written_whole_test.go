//go:build unix

package server

import (
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/iacrypto"
)

// A symbolic link at the file's name is replaced, not written through: only a
// write that goes to a temporary beside it, is flushed and renamed does that.
// os.WriteFile follows the link and rewrites the target in place, which is
// also what leaves a file empty or torn when the process dies mid-write.
func plantALink(t *testing.T, path string) (victim string) {
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

func requireReplacedNotWrittenThrough(t *testing.T, path, victim string) {
	t.Helper()
	if b, _ := os.ReadFile(victim); string(b) != "untouched" {
		t.Fatalf("written in place, through a link: victim now %q", b)
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("want a regular 0600 file, got %v (%v)", fi, err)
	}
}

func TestThePostQuantumCommitmentIsWrittenWhole(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	victim := plantALink(t, s.postQuantumCommitmentPath())
	if err := s.recordPostQuantumCommitment(&iacrypto.PostQuantumNextKey{Digest: "D", Verkey: "V"}); err != nil {
		t.Fatal(err)
	}
	requireReplacedNotWrittenThrough(t, s.postQuantumCommitmentPath(), victim)
}

func TestTheDirectAllowlistIsWrittenWhole(t *testing.T) {
	dir := t.TempDir()
	victim := plantALink(t, filepath.Join(dir, directAllowlistFileName))
	al, _ := loadDirectAllowlist(dir)
	// Something else's file at the old fixed temporary name: the write must
	// use a name of its own and leave it alone.
	other := al.path + ".tmp"
	if err := os.WriteFile(other, []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := al.Allow(allowedAID); err != nil {
		t.Fatal(err)
	}
	requireReplacedNotWrittenThrough(t, al.path, victim)
	if b, _ := os.ReadFile(other); string(b) != "not ours" {
		t.Fatalf("the write used a fixed temporary name and clobbered %q", b)
	}
}

// When the list cannot be written, the set the listener answers from is the
// one that is on disk: memory changes after the write, not before it.
func TestAFailedAllowlistWriteLeavesTheSetAsItWas(t *testing.T) {
	dir := t.TempDir()
	al, _ := loadDirectAllowlist(dir)
	if err := al.Allow(allowedAID); err != nil {
		t.Fatal(err)
	}
	// Make the write fail: a directory now sits where the file goes.
	if err := os.Remove(al.path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(al.path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := al.Allow(notAllowedAID); err == nil {
		t.Fatal("the write should have failed")
	}
	if al.Has(notAllowedAID) {
		t.Fatal("answers for an identifier that was never saved")
	}
	if err := al.Remove(allowedAID); err == nil {
		t.Fatal("the write should have failed")
	}
	if !al.Has(allowedAID) {
		t.Fatal("dropped an identifier whose removal was never saved")
	}
}
