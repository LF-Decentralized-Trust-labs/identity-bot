package secureenclave

import (
	"bytes"
	"os"
	"testing"
)

// A seed that is stored and cannot be read right now is reported, and never
// replaced: replacing it would destroy every key derived from it.
func TestAStoredSeedThatCannotBeReadIsNeverReplaced(t *testing.T) {
	dir := t.TempDir()
	first, err := EnsureRootSeed(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := rootSeedPath(dir)
	before, _ := os.ReadFile(path)
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureRootSeed(dir); err == nil {
		t.Fatal("a seed that cannot be read was not reported")
	}
	os.Chmod(path, 0o600)
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("the stored seed was replaced")
	}
	again, err := EnsureRootSeed(dir)
	if err != nil || !bytes.Equal(again, first) {
		t.Fatal("the seed read back is not the one stored")
	}
}
