package backup

import (
	"os"
	"path/filepath"
	"testing"
)

// The Identity Agent starts no container or program of its own, so a backup no
// longer lists a sandbox directory's entries as a "sandbox_index" section, even
// when an earlier build left that directory behind. An older archive that has the section is still
// read: the restore takes the sections it knows by name and ignores the rest.
func TestAnArchiveWritesNoSandboxIndex(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sandbox", "an-app"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := &Collector{DataDir: dir}
	bundle := &PayloadBundle{Sections: map[string][]byte{}}
	if _, err := c.collectTier3(bundle, CollectOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := bundle.Sections["sandbox_index"]; ok {
		t.Error("a sandbox_index section was written")
	}
}
