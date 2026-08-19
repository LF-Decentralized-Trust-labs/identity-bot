package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ACT2 — backup-only device stores opaque blob; cannot unwrap BEK.
func TestBackupOnlyDeviceOpaqueStorage(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, nil)

	// This machine has to have offered before it holds anything for anybody,
	// and the identifier has to be one. Both were added when the receiving path
	// was found accepting archives from any host that could reach it, filed
	// under a caller-chosen path. What this test is actually about — that the
	// stored bytes are opaque and no key material lands beside them — is
	// unchanged.
	owner := "E" + strings.Repeat("A", 43)
	cfg, err := svc.ConfigStore.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Offer = Offer{Accepting: true, AcceptingNewIdentities: true, ReserveBytes: 1024}
	if err := svc.ConfigStore.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	ciphertext := []byte{0xDE, 0xAD, 0xBE, 0xEF} // simulated encrypted archive
	path, err := svc.ReceiveArchive(owner, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(ciphertext) {
		t.Fatal("stored bytes must match ciphertext exactly")
	}

	// Device has no decrypt API — OpenArchive requires mnemonic/BEK.
	_, _, err = OpenArchive(stored, OpenRequest{})
	if err == nil {
		t.Fatal("backup-only device must not decrypt without recovery credentials")
	}

	// No key material written alongside archive.
	entries, _ := os.ReadDir(filepath.Join(dir, "backup_receive", owner))
	if len(entries) != 1 {
		t.Fatalf("expected 1 opaque file, got %d", len(entries))
	}
}
