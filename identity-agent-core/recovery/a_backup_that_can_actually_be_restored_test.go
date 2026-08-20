package recovery

import (
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/store"
)

// Backing up was proven end to end. Restoring was not.
//
// Every other test in this package builds its payload by hand, and the live
// run stopped at the waiting period — so nothing had ever taken a real
// identity, put it through the real collector, and asked the machine on the
// other side whether it came back. Two separate faults were sitting in that
// gap, either of which loses an identity that has a valid backup.

const testPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

func machineWithAnIdentity(t *testing.T, aid string) (string, *store.SQLiteStore) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveIdentity(store.IdentityState{
		AID: aid, PublicKey: "dGVzdA==", NextKeyDigest: "digest",
		Created: "2026-01-01T00:00:00Z", EventCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	return dir, st
}

func archiveOf(t *testing.T, dir string, st store.Store) []byte {
	t.Helper()
	c := &backup.Collector{DataDir: dir, Store: st}
	opts := backup.CollectOptions{Tiers: []string{backup.TierCritical, backup.TierImportant}}
	bundle, pointers, err := c.Collect(opts)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.CreateArchive(opts, backup.ExportRequest{
		Mnemonic: testPhrase, Tiers: opts.Tiers,
		Bundle: bundle, ExternalPointers: pointers,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res.Bytes
}

// The database inside an archive must hold what the agent had committed.
//
// identity.db runs in WAL mode: a committed transaction lands in
// identity.db-wal and reaches identity.db only at a checkpoint, on SQLite's
// own schedule. The collector read the main file alone — so everything since
// the last checkpoint was missing, which on a young database is everything.
//
// Nothing downstream could see it. Verification compares the archive against
// what was collected, and an empty database round-trips through encryption
// and digesting perfectly: valid archive, honest manifest, no data.
func TestTheArchivedDatabaseHasWhatTheAgentCommitted(t *testing.T) {
	dir, st := machineWithAnIdentity(t, "EWrittenJustNow")
	defer st.Close()

	c := &backup.Collector{DataDir: dir, Store: st}
	bundle, _, err := c.Collect(backup.CollectOptions{Tiers: []string{backup.TierCritical}})
	if err != nil {
		t.Fatal(err)
	}
	raw := bundle.Sections["sqlite_identity_db"]
	if len(raw) == 0 {
		t.Fatal("the archive carries no database at all")
	}

	// Open ONLY those bytes, with no -wal beside them — which is the state a
	// restore leaves them in, and the only state they can be read in.
	fresh := t.TempDir()
	if err := writeDB(fresh, raw); err != nil {
		t.Fatal(err)
	}
	restored, err := store.NewSQLiteStore(fresh)
	if err != nil {
		t.Fatalf("the archived database will not open: %v", err)
	}
	defer restored.Close()

	got, err := restored.GetIdentity()
	if err != nil {
		t.Fatalf("the archived database is unreadable: %v", err)
	}
	if got == nil || got.AID != "EWrittenJustNow" {
		t.Fatalf("the archived database is missing what the agent had committed: %+v", got)
	}
}

// The whole way: a real identity, the real collector, and a machine that has
// never held it.
func TestAnIdentityThatWasBackedUpComesBack(t *testing.T) {
	oldDir, oldStore := machineWithAnIdentity(t, "EMyRealIdentity")
	if err := oldStore.SaveContact(store.ContactRecord{
		AID: "EAlice", Alias: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	archive := archiveOf(t, oldDir, oldStore)
	oldStore.Close()

	newDir := t.TempDir()
	newStore, err := store.NewSQLiteStore(newDir)
	if err != nil {
		t.Fatal(err)
	}
	defer newStore.Close()

	payload, err := RestoreFromArchive(archive, OpenRequest{Mnemonic: testPhrase})
	if err != nil {
		t.Fatalf("the archive would not open from its own phrase: %v", err)
	}
	if err := NewService(newDir, newStore, nil).applyPayload(payload); err != nil {
		t.Fatalf("the restore failed: %v", err)
	}

	got, err := newStore.GetIdentity()
	if err != nil {
		t.Fatalf("the restored database cannot be read: %v", err)
	}
	if got == nil || got.AID != "EMyRealIdentity" {
		t.Fatalf("the identity did not come back: %+v", got)
	}
	contacts, err := newStore.GetContacts()
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) == 0 {
		t.Fatal("the contacts did not come back")
	}
}

// The archive holds the same data twice, and the two copies must not fight.
//
// An archive carries the identity database AND parsed sections describing the
// same rows, so whichever is applied second wins. The parsed sections are the
// copy this code understands and can fail loudly on, so they have the final
// say, and this pins that ordering.
//
// WHAT THIS DOES NOT CATCH, stated because the difference matters. Reverting
// the restore to the old raw overwrite leaves this passing: the write-ahead
// log of the connection the restore ran on still holds the section writes and
// checkpoints them back over the replaced file. So this pins the intended
// ordering for the future; it is not what proved the old path wrong. The test
// that did that is the unknown-table one below, which fails deterministically.
func TestTheDatabaseDoesNotOverwriteWhatTheSectionsRestored(t *testing.T) {
	oldDir, oldStore := machineWithAnIdentity(t, "EWhatTheDatabaseHolds")
	archive := archiveOf(t, oldDir, oldStore)
	oldStore.Close()

	payload, err := RestoreFromArchive(archive, OpenRequest{Mnemonic: testPhrase})
	if err != nil {
		t.Fatal(err)
	}
	// The two copies now disagree. Whichever is applied second wins, and it
	// has to be this one.
	payload.Identity.AID = "EWhatTheSectionsSay"

	newDir := t.TempDir()
	newStore, err := store.NewSQLiteStore(newDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewService(newDir, newStore, nil).applyPayload(payload); err != nil {
		t.Fatal(err)
	}
	// Read it back through a NEW connection rather than the one the restore
	// ran on. That connection's write-ahead log still holds everything the
	// sections wrote, so it answers correctly even when the file underneath it
	// has been replaced — which is precisely the damage being tested for, and
	// it stays invisible until the next process opens the database.
	newStore.Close()
	reopened, err := store.NewSQLiteStore(newDir)
	if err != nil {
		t.Fatalf("the restored database will not reopen: %v", err)
	}
	defer reopened.Close()

	got, err := reopened.GetIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.AID != "EWhatTheSectionsSay" {
		t.Fatalf("the database copy overwrote the restored sections: got %+v", got)
	}
}

// A restore must leave a database the next process can open.
//
// The restore runs against a live connection, and the database has to survive
// both that connection and the next one to start — which is where a
// write-ahead log that disagrees with its database would surface.
//
// Like the test above, this does not fail against the old raw overwrite; in
// practice the log checkpoints cleanly and the known tables survive. It is
// here to hold the property, not because it caught anything.
func TestTheDatabaseIsStillUsableAfterARestore(t *testing.T) {
	oldDir, oldStore := machineWithAnIdentity(t, "EStillWorks")
	archive := archiveOf(t, oldDir, oldStore)
	oldStore.Close()

	newDir := t.TempDir()
	newStore, err := store.NewSQLiteStore(newDir)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := RestoreFromArchive(archive, OpenRequest{Mnemonic: testPhrase})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewService(newDir, newStore, nil).applyPayload(payload); err != nil {
		t.Fatal(err)
	}

	// Still writable through the connection that was open across the restore.
	if err := newStore.SaveContact(store.ContactRecord{
		AID: "EAfterwards", Alias: "Afterwards",
	}); err != nil {
		t.Fatalf("the database is unusable after the restore: %v", err)
	}
	newStore.Close()

	// And still openable by the next process to start, which is where a
	// mismatched sidecar shows up.
	reopened, err := store.NewSQLiteStore(newDir)
	if err != nil {
		t.Fatalf("the restored database will not reopen: %v", err)
	}
	defer reopened.Close()
	if _, err := reopened.GetContacts(); err != nil {
		t.Fatalf("the restored database is damaged: %v", err)
	}
}

// This core cannot know what software built on top of it keeps in here.
//
// The sweep exists because naming the files to collect drops exactly the ones
// a downstream build added. The same holds for tables: a restore that copied
// only the tables this package can parse would lose them.
func TestATableThisCoreDoesNotKnowAboutComesBack(t *testing.T) {
	oldDir, oldStore := machineWithAnIdentity(t, "EWithExtras")
	if _, err := oldStore.DB().Exec(
		`CREATE TABLE downstream_notes (id TEXT PRIMARY KEY, body TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := oldStore.DB().Exec(
		`INSERT INTO downstream_notes VALUES ('n1', 'written by something else')`); err != nil {
		t.Fatal(err)
	}
	archive := archiveOf(t, oldDir, oldStore)
	oldStore.Close()

	newDir := t.TempDir()
	newStore, err := store.NewSQLiteStore(newDir)
	if err != nil {
		t.Fatal(err)
	}
	defer newStore.Close()
	payload, err := RestoreFromArchive(archive, OpenRequest{Mnemonic: testPhrase})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewService(newDir, newStore, nil).applyPayload(payload); err != nil {
		t.Fatal(err)
	}

	var body string
	if err := newStore.DB().QueryRow(
		`SELECT body FROM downstream_notes WHERE id='n1'`).Scan(&body); err != nil {
		t.Fatalf("a table this core does not know about was lost: %v", err)
	}
	if body != "written by something else" {
		t.Fatalf("it came back wrong: %q", body)
	}
}

func writeDB(dir string, raw []byte) error {
	return os.WriteFile(filepath.Join(dir, "identity.db"), raw, 0600)
}
