package server

import (
	"testing"

	"identity-agent-core/store"
)

// A witness holding endpoint records needs a real store — the whole point is
// that it can answer later.
func witnessWithStore(t *testing.T) *CoreServer {
	t.Helper()
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	return &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: dir, DataStore: ds}
}
