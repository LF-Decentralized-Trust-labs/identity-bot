package remote

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

type mockBackend struct {
	mu    sync.Mutex
	files map[string][]byte
}

func (m *mockBackend) Push(ctx context.Context, objectKey string, data []byte) error {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.files == nil {
		m.files = map[string][]byte{}
	}
	m.files[objectKey] = append([]byte(nil), data...)
	return nil
}

func (m *mockBackend) Pull(ctx context.Context, objectKey string) ([]byte, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.files[objectKey]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return append([]byte(nil), data...), nil
}

func (m *mockBackend) List(ctx context.Context, prefix string) ([]string, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []string
	for k := range m.files {
		if prefix == "" || len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func TestCloudUploadMock(t *testing.T) {
	mock := &mockBackend{files: map[string][]byte{}}
	dest := DestinationConfig{
		Provider: "s3",
		Bucket:   "test-bucket",
		Prefix:   "identity-aid",
	}
	ciphertext := []byte{0x10, 0x20, 0x30, 0x40}
	key := ArchiveObjectKey(dest, "full")
	if err := mock.Push(context.Background(), key, ciphertext); err != nil {
		t.Fatal(err)
	}
	pulled, err := mock.Pull(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if string(pulled) != string(ciphertext) {
		t.Fatal("mock pull must return encrypted archive bytes unchanged")
	}
	latest, err := LatestArchiveKey(context.Background(), mock, dest.Prefix)
	if err != nil {
		t.Fatal(err)
	}
	if latest != key {
		t.Fatalf("latest key %s != %s", latest, key)
	}
}
