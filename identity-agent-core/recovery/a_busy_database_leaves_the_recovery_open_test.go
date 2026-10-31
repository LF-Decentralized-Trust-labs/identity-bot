package recovery

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/sqlitedb"
)

// databaseBytes is a database holding one row, as an archive carries it.
func databaseBytes(t *testing.T, row string) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "copy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE messages (body TEXT); INSERT INTO messages (body) VALUES (?)`, row); err != nil {
		t.Fatal(err)
	}
	db.Close()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A database held by a writer for longer than a restore waits stops the
// restore, as ordinary contention, before the key material or the identity
// is touched, and leaves the recovery open: it is not marked failed and keeps
// its archive, so asking again once the writer is done completes it. Marked
// failed, a recovery that had waited days had to start the wait again.
func TestABusyDatabaseLeavesTheRecoveryOpen(t *testing.T) {
	defer func(was time.Duration) { backup.RestoreWaitsForABusyDatabase = was }(backup.RestoreWaitsForABusyDatabase)
	backup.RestoreWaitsForABusyDatabase = 200 * time.Millisecond

	dir := t.TempDir()
	svc := NewService(dir, nil, nil)
	archive := buildTestArchiveWith(t, testMnemonic, nil, map[string][]byte{
		backup.FileSectionPrefix + "ai-memory.db": databaseBytes(t, "a conversation from the archive"),
	})
	sess, err := svc.Start(StartRequest{ArchiveB64: base64.StdEncoding.EncodeToString(archive), Mnemonic: testMnemonic})
	if err != nil {
		t.Fatal(err)
	}
	svc.CancelGate.Now = func() time.Time { return time.Now().Add(96 * time.Hour) }
	svc.Rotation.MarkCompleted(sess.ID, RotationResult{})

	// The add-on's store, open, with a writer holding it.
	live, err := sqlitedb.Open(filepath.Join(dir, "ai-memory.db"), sqlitedb.Settings{})
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if _, err := live.Exec(`CREATE TABLE messages (body TEXT); INSERT INTO messages (body) VALUES ('a conversation on this machine')`); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	writer, err := live.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.ExecContext(ctx, `BEGIN IMMEDIATE; INSERT INTO messages (body) VALUES ('mid-write')`); err != nil {
		t.Fatal(err)
	}

	_, err = svc.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic})
	var again *ErrRestoreCanBeRetried
	if !errors.As(err, &again) {
		t.Fatalf("a busy database ended the restore with %v, not as one to try again", err)
	}
	if got, gerr := svc.GetSession(sess.ID); gerr != nil || got.State == SessionFailed {
		t.Fatalf("the recovery did not stay open: %+v (%v)", got, gerr)
	}

	if _, err := writer.ExecContext(ctx, `ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	writer.Close()

	if _, err := svc.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic}); err != nil {
		t.Fatalf("asking again did not finish the recovery: %v", err)
	}
	var body string
	if err := live.QueryRow(`SELECT body FROM messages`).Scan(&body); err != nil || body != "a conversation from the archive" {
		t.Fatalf("the open store reads %q (%v)", body, err)
	}
}
