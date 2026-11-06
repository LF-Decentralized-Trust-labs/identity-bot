//go:build unix

package backup

import (
	"os"
	"path/filepath"
	"testing"
)

// A symbolic link at the file's name is replaced, not written through: only a
// write to a temporary beside it, flushed and renamed does that. os.WriteFile
// rewrites the target in place, which leaves it empty or torn if the process
// dies mid-write.
func TestTheBackupSettingsAreWrittenWhole(t *testing.T) {
	cs := NewConfigStore(t.TempDir())
	cases := map[string]func() error{
		cs.deltaStatePath(): func() error { return cs.SaveDeltaState(DeltaState{}) },
		cs.configPath():     func() error { return cs.SaveConfig(Config{}) },
		cs.historyPath():    func() error { return cs.AppendHistory(HistoryEntry{}) },
	}
	for path, save := range cases {
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, path); err != nil {
			t.Fatal(err)
		}
		if err := save(); err != nil {
			t.Fatalf("%s: %v", filepath.Base(path), err)
		}
		if b, _ := os.ReadFile(victim); string(b) != "untouched" {
			t.Fatalf("%s written in place, through a link: victim now %q", filepath.Base(path), b)
		}
		if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: want a regular 0600 file, got %v (%v)", filepath.Base(path), fi, err)
		}
	}
}
