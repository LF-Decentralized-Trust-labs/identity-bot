package sqlitedb

import (
	"path/filepath"
	"testing"
)

// Every connection the pool opens has the settings, not only the first.
func TestEveryConnectionHasTheSettings(t *testing.T) {
	for _, fk := range []bool{true, false} {
		db, err := Open(filepath.Join(t.TempDir(), "x.db"), Settings{ForeignKeys: fk})
		if err != nil {
			t.Fatal(err)
		}
		got, err := InForce(db, 3)
		db.Close()
		if err != nil {
			t.Fatal(err)
		}
		want := "5000 wal 1 0"
		if fk {
			want = "5000 wal 1 1"
		}
		for i, g := range got {
			if g != want {
				t.Fatalf("connection %d has %q, want %q", i, g, want)
			}
		}
	}
}
