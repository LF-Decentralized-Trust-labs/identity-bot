package sandbox

import (
	"testing"

	"identity-agent-core/sqlitedb"
)

// Every connection of the governance log waits for a busy database, journals
// by WAL and enforces foreign keys.
func TestTheSandboxStoresConnectionsAllHaveTheSettings(t *testing.T) {
	st, err := NewSandboxStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := sqlitedb.InForce(st.DB(), 3)
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range got {
		if s != "5000 wal 1 1" {
			t.Fatalf("connection %d has %q", i, s)
		}
	}
}
