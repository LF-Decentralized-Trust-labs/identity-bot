package backup

import (
	"os"
	"path/filepath"
	"testing"
)

// ACT2 — backup-only device stores opaque blob; cannot unwrap BEK.
func TestBackupOnlyDeviceOpaqueStorage(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, nil)

	ciphertext := []byte{0xDE, 0xAD, 0xBE, 0xEF} // simulated encrypted archive
	path, err := svc.ReceiveArchive("Eowner123", ciphertext)
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
	entries, _ := os.ReadDir(filepath.Join(dir, "backup_receive", "Eowner123"))
	if len(entries) != 1 {
		t.Fatalf("expected 1 opaque file, got %d", len(entries))
	}
}