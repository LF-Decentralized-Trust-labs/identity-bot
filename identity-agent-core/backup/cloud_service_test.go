package backup

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

type mockRemoteBackend struct {
	mu    sync.Mutex
	files map[string][]byte
}

func (m *mockRemoteBackend) Push(ctx context.Context, objectKey string, data []byte) error {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[objectKey] = append([]byte(nil), data...)
	return nil
}

func (m *mockRemoteBackend) Pull(ctx context.Context, objectKey string) ([]byte, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.files[objectKey]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return append([]byte(nil), data...), nil
}

func (m *mockRemoteBackend) List(ctx context.Context, prefix string) ([]string, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []string
	for k := range m.files {
		keys = append(keys, k)
	}
	return keys, nil
}

func TestServiceCloudPushUsesEncryptedBytes(t *testing.T) {
	dir := t.TempDir()
	svc := NewService(dir, nil)
	credID, err := svc.SaveDestinationCredentials(RemoteCredentialSecrets{
		AccessKey: "key",
		SecretKey: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}

	mock := &mockRemoteBackend{files: map[string][]byte{}}
	origFactory := remoteBackendFactory
	remoteBackendFactory = func(dest Destination, creds RemoteCredentialSecrets) (remoteBackend, error) {
		return mock, nil
	}
	defer func() { remoteBackendFactory = origFactory }()

	dest := Destination{
		ID:            "cloud-1",
		Type:          DestCloudUser,
		Enabled:       true,
		CloudProvider: "s3",
		CloudBucket:   "bucket",
		CloudPrefix:   "aid",
		CredentialID:  credID,
	}
	encrypted := []byte{0xAA, 0xBB, 0xCC}
	result := &ExportResult{
		Bytes:        encrypted,
		SnapshotType: SnapshotFull,
		Size:         len(encrypted),
	}
	if err := svc.pushCloudDestination(dest, result); err != nil {
		t.Fatal(err)
	}
	if len(mock.files) != 1 {
		t.Fatalf("expected 1 uploaded object, got %d", len(mock.files))
	}
	for _, data := range mock.files {
		if len(data) != len(encrypted) {
			t.Fatal("uploaded archive size mismatch")
		}
	}
}
