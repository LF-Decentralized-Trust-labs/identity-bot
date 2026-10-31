package recovery

import (
	"database/sql"
	"path/filepath"
	"testing"

	"identity-agent-core/sqlitedb"
	"identity-agent-core/store"
)

func openStore(t *testing.T, path, row string) *sql.DB {
	t.Helper()
	db, err := sqlitedb.Open(path, sqlitedb.Settings{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS messages (body TEXT); INSERT INTO messages (body) VALUES (?)`, row); err != nil {
		t.Fatal(err)
	}
	return db
}

// A whole restore, onto a machine where an add-on's database is open with
// its own rows and a live log beside it, as the AI conversations are while
// the Identity Agent runs. The open connection sees the archive's rows and
// can carry on; written over as a file, it kept its own rows, the archive's
// were silently lost, and its next write went into the replaced file.
func TestARestoreReachesADatabaseThatIsOpen(t *testing.T) {
	oldDir, oldStore := machineWithAnIdentity(t, "EOpenDatabase")
	old := openStore(t, filepath.Join(oldDir, "ai-memory.db"), "a conversation from the archive")
	archive := archiveWithTheDefaultTiers(t, oldDir, oldStore)
	old.Close()
	oldStore.Close()

	newDir := t.TempDir()
	newStore, err := store.NewSQLiteStore(newDir)
	if err != nil {
		t.Fatal(err)
	}
	defer newStore.Close()
	live := openStore(t, filepath.Join(newDir, "ai-memory.db"), "a conversation on this machine")
	defer live.Close()

	payload, err := RestoreFromArchive(archive, OpenRequest{Mnemonic: testPhrase})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewService(newDir, newStore, nil).applyPayload(payload); err != nil {
		t.Fatalf("the restore failed: %v", err)
	}

	var body string
	if err := live.QueryRow(`SELECT body FROM messages`).Scan(&body); err != nil || body != "a conversation from the archive" {
		t.Fatalf("the open connection reads %q (%v), not the archive's conversation", body, err)
	}
	if _, err := live.Exec(`INSERT INTO messages (body) VALUES ('after the restore')`); err != nil {
		t.Fatalf("the open connection cannot write after the restore: %v", err)
	}
	var n int
	if err := live.QueryRow(`SELECT count(*) FROM messages`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("%d rows (%v), want the archive's and the one written after", n, err)
	}
}
