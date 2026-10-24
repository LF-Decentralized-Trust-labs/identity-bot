package conversation

import (
	"testing"

	"identity-agent-core/sqlitedb"
)

// The conversation record's connection waits for a busy database and
// journals by WAL.
func TestTheConversationRecordHasTheSettings(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	got, err := sqlitedb.InForce(st.db, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range got {
		if s != "5000 wal 1 0" {
			t.Fatalf("connection %d has %q", i, s)
		}
	}
}
