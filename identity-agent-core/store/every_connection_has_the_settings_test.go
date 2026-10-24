package store

import (
	"testing"

	"identity-agent-core/sqlitedb"
)

// Every connection of the identity store and the AI memory store waits for a
// busy database, journals by WAL and enforces foreign keys.
func TestTheStoresConnectionsAllHaveTheSettings(t *testing.T) {
	ids, err := NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ids.Close()
	mem, err := NewAIMemoryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]func() ([]string, error){
		"identity":  func() ([]string, error) { return sqlitedb.InForce(ids.DB(), 3) },
		"ai memory": func() ([]string, error) { return sqlitedb.InForce(mem.db, 3) },
	} {
		settings, err := got()
		if err != nil {
			t.Fatal(err)
		}
		for i, s := range settings {
			if s != "5000 wal 1 1" {
				t.Fatalf("the %s store's connection %d has %q", name, i, s)
			}
		}
	}
}
