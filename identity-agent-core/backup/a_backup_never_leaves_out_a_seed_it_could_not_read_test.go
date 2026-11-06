package backup

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/secureenclave"
)

// A backup either carries the root seed's recovery path or fails and says why.
//
// The collector used to skip the root_seed section on ANY error, so a computer
// that refused its own seed (a production build holding one stored unwrapped)
// produced a valid archive with no seed in it, and nobody learned that until
// they tried to recover. Only "there is no seed here" may leave the section out.
func TestABackupFailsRatherThanLeaveOutASeedItCouldNotRead(t *testing.T) {
	restore := secureenclave.UseSeedWrapper(nil) // nothing here can wrap a seed
	defer restore()

	c := testCollector(t)
	p := filepath.Join(c.DataDir, "secureenclave", "root_seed.key")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	// A legacy plain seed file: a production build refuses to use it.
	if err := os.WriteFile(p, bytes.Repeat([]byte{7}, 64), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Collect(CollectOptions{Tiers: []string{TierCritical}}); err == nil {
		t.Fatal("a backup was made without the seed it could not read")
	} else if !secureenclave.IsRootSeedRefusal(err) {
		t.Fatalf("the backup failed, but not with the seed's own reason: %v", err)
	}
}

// And a computer that never had a seed still makes a backup.
func TestABackupWithNoSeedStillMakesAnArchive(t *testing.T) {
	c := testCollector(t)
	bundle, _, err := c.Collect(CollectOptions{Tiers: []string{TierCritical}})
	if err != nil {
		t.Fatalf("no seed was ever stored, and the backup failed: %v", err)
	}
	if _, has := bundle.Sections["root_seed"]; has {
		t.Fatal("a root_seed section appeared from nowhere")
	}
}
