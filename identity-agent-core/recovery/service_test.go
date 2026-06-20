package recovery

import (
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/backup"
)

func TestRetrieveFromBackupOnlyDevice(t *testing.T) {
	dir := t.TempDir()
	backupSvc := backup.NewService(dir, nil)
	raw := []byte{0x49, 0x41, 0x42, 0x31, 0x00, 0x01}
	path, err := backupSvc.ReceiveArchive("Eowner123", raw)
	if err != nil {
		t.Fatal(err)
	}
	_ = path

	svc := NewService(dir, nil, backupSvc)
	resp, err := svc.Retrieve(RetrieveRequest{
		Source:      SourceBackupOnlyDevice,
		IdentityAID: "Eowner123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.SizeBytes != len(raw) {
		t.Fatalf("size %d", resp.SizeBytes)
	}
}

func TestRetrieveFromLocalFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "backup.iab")
	payload := []byte("local-archive-bytes")
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}

	svc := NewService(dir, nil, nil)
	resp, err := svc.Retrieve(RetrieveRequest{
		Source:    SourceLocalFile,
		LocalPath: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Source != SourceLocalFile {
		t.Fatalf("source %s", resp.Source)
	}
}

func TestRetrieveFromCloudStub(t *testing.T) {
	svc := NewService(t.TempDir(), nil, nil)
	_, err := svc.Retrieve(RetrieveRequest{Source: SourceCloud, CloudRef: "s3://bucket/key"})
	if err == nil {
		t.Fatal("cloud retrieve stub must error")
	}
}

func TestRootAIDRotationStub(t *testing.T) {
	_, err := RotateRootAID(RootAIDRotationRequest{RecoverySessionID: "sess-1"})
	if err == nil {
		t.Fatal("root-AID rotation stub must error")
	}
	if RootAIDRotationAvailable() {
		t.Fatal("root-AID rotation should not be available yet")
	}
}