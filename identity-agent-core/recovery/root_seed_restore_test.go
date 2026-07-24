package recovery

import (
	"bytes"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/secureenclave"
	"identity-agent-core/store"
)

// The backup collector captures the root keystore seed, and restore reseats it on
// the target device — so every HD-derived key re-derives after device loss. This
// is the recovery path that must never depend on the old device's hardware.
func TestRootSeedBackupAndReseat(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(200 - i)
	}

	// Old device: seed exists; the collector captures it.
	oldDir := t.TempDir()
	if err := secureenclave.StoreRootSeed(oldDir, seed); err != nil {
		t.Fatalf("store on old device: %v", err)
	}
	st, err := store.NewSQLiteStore(oldDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	c := &backup.Collector{DataDir: oldDir, Store: st}
	bundle, _, err := c.Collect(backup.DefaultCollectOptions([]string{backup.TierCritical}))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	got, ok := bundle.Sections["root_seed"]
	if !ok || !bytes.Equal(got, seed) {
		t.Fatalf("root_seed section missing or wrong (present=%v)", ok)
	}

	// New device: restore reseats the seed from the archive payload.
	newDir := t.TempDir()
	svc := &Service{DataDir: newDir}
	if err := svc.applyPayload(&RestoredPayload{Bundle: bundle}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	reseated, err := secureenclave.LoadRootSeed(newDir)
	if err != nil || !bytes.Equal(reseated, seed) {
		t.Fatalf("reseated seed mismatch: %v", err)
	}
}
