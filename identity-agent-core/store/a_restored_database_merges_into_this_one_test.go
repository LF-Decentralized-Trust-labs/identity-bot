package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// snapshotOf takes a self-contained copy of a store's database, the way the
// collector does, so these tests exercise the real shape of a restore.
func snapshotOf(t *testing.T, s *SQLiteStore) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.db")
	if _, err := s.db.Exec("VACUUM INTO ?", path); err != nil {
		t.Fatal(err)
	}
	return path
}

func openStore(t *testing.T) (string, *SQLiteStore) {
	t.Helper()
	dir := t.TempDir()
	s, err := NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return dir, s
}

// A backup made by a newer build must not be half-applied.
//
// The schema version is bookkeeping held in an ordinary table. Copying it
// across records every migration the backup had run as applied — while the
// columns those migrations added stay behind, because whole tables are copied
// and a column added by ALTER TABLE is not a table. The binary then skips the
// migrations it needs, and upgrading later does not help, because the
// bookkeeping already says they ran. The database is wedged permanently.
func TestABackupFromANewerBuildIsRefusedRatherThanHalfApplied(t *testing.T) {
	_, from := openStore(t)
	if _, err := from.db.Exec(
		`INSERT INTO identity_schema_migrations (version, description, applied_at)
		 VALUES (?, 'from the future', '2030-01-01')`,
		newestKnownMigration()+5); err != nil {
		t.Fatal(err)
	}
	snap := snapshotOf(t, from)

	_, into := openStore(t)
	err := into.ImportSnapshot(snap)
	if err == nil {
		t.Fatal("a backup from a newer build was accepted")
	}
	// And it says something a person can act on rather than a SQL error.
	for _, want := range []string{"newer version", "update the software"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not explain itself: %q", err)
		}
	}
}

// A backup from the previous schema version restores.
//
// The copy intersects the columns both sides have, which is wrong rather than
// merely lossy when a migration RENAMES a column: the old name matches nothing,
// so the insert omits the new one — and if it is NOT NULL the restore fails
// with a constraint error, from a backup the version gate explicitly accepts.
// Migration 34 renames adopted_agents.delegated_aid to signs_as_aid, so a
// backup from before it exercises exactly that.
//
// The fix is to run this build's migrations against the backup BEFORE copying,
// so the two schemas match and the rename is performed rather than worked
// around.
func TestABackupFromThePreviousSchemaVersionRestores(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.db")
	old, err := sqlOpenForTest(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyMigrationsUpTo(old, newestKnownMigration()-1); err != nil {
		t.Fatal(err)
	}
	// A row stored under the name the column had back then.
	if _, err := old.Exec(
		`INSERT INTO adopted_agents (aid, delegated_aid, url, kind, label)
		 VALUES ('EMachine', 'ESignsAs', 'https://example', 'computer', 'the laptop')`); err != nil {
		t.Fatalf("this test no longer matches the schema it targets: %v", err)
	}
	old.Close()

	_, into := openStore(t)
	if err := into.ImportSnapshot(path); err != nil {
		t.Fatalf("a backup from the previous schema version would not restore: %v", err)
	}

	var signsAs string
	if err := into.db.QueryRow(
		`SELECT signs_as_aid FROM adopted_agents WHERE aid='EMachine'`).Scan(&signsAs); err != nil {
		t.Fatalf("the row did not come back: %v", err)
	}
	if signsAs != "ESignsAs" {
		t.Fatalf("the renamed column did not carry its value: %q", signsAs)
	}
}

// applyMigrationsUpTo builds a database as an older build would have left it.
func applyMigrationsUpTo(db *sql.DB, version int) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS identity_schema_migrations (
		version INTEGER PRIMARY KEY, description TEXT, applied_at TEXT)`); err != nil {
		return err
	}
	for _, m := range identityMigrations {
		if m.Version > version {
			break
		}
		if _, err := db.Exec(m.SQL); err != nil {
			return fmt.Errorf("migration %d: %w", m.Version, err)
		}
		if _, err := db.Exec(
			`INSERT INTO identity_schema_migrations (version, description, applied_at)
			 VALUES (?, ?, '2026-01-01')`, m.Version, m.Description); err != nil {
			return err
		}
	}
	return nil
}

// Tables with no primary key are replaced, not appended to.
//
// INSERT OR REPLACE resolves against a primary key or a unique index. Four
// tables here have neither — identity, profile, settings, endpoint — so there
// is no conflict to detect and every restore adds a second copy of every row.
// profile and endpoint have no parsed section either, so this copy is the only
// way they come back, and the local placeholder sitting at a lower rowid made
// the restored one unreachable.
func TestATableWithNoPrimaryKeyDoesNotAccumulateCopies(t *testing.T) {
	_, from := openStore(t)
	if err := from.SaveProfile(ProfileData{FullName: "The Real One"}); err != nil {
		t.Fatal(err)
	}
	snap := snapshotOf(t, from)

	_, into := openStore(t)
	if err := into.SaveProfile(ProfileData{FullName: "Placeholder"}); err != nil {
		t.Fatal(err)
	}
	// Twice, because a retry after a transient failure is a normal thing.
	for i := 0; i < 2; i++ {
		if err := into.ImportSnapshot(snap); err != nil {
			t.Fatal(err)
		}
	}

	var rows int
	if err := into.db.QueryRow(`SELECT COUNT(*) FROM profile`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("profile has %d rows after restoring twice", rows)
	}
	got, err := into.GetProfile()
	if err != nil {
		t.Fatal(err)
	}
	if got.FullName != "The Real One" {
		t.Fatalf("the backed-up profile did not come back: %q", got.FullName)
	}
}

// A virtual table anywhere in the database must not abort the restore.
//
// A virtual table is stored as several ordinary-looking shadow tables, which
// sqlite_master lists BEFORE the virtual table itself. Creating those as plain
// tables makes the real CREATE VIRTUAL TABLE fail with "shadow table already
// exists" — and that error aborted the whole restore, having applied nothing.
// This lands on exactly the case the change exists for: a table a build on top
// of this core keeps in here.
func TestAVirtualTableDoesNotAbortTheRestore(t *testing.T) {
	_, from := openStore(t)
	if _, err := from.db.Exec(
		`CREATE VIRTUAL TABLE downstream_fts USING fts5(body)`); err != nil {
		t.Skipf("this build has no FTS5: %v", err)
	}
	if _, err := from.db.Exec(
		`INSERT INTO downstream_fts (body) VALUES ('findable text')`); err != nil {
		t.Fatal(err)
	}
	if err := from.SaveIdentity(IdentityState{
		AID: "EWithFTS", PublicKey: "dGVzdA==", NextKeyDigest: "d",
		Created: "2026-01-01T00:00:00Z", EventCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	snap := snapshotOf(t, from)

	_, into := openStore(t)
	if err := into.ImportSnapshot(snap); err != nil {
		t.Fatalf("a virtual table aborted the restore: %v", err)
	}
	// The rest of the restore actually happened.
	got, err := into.GetIdentity()
	if err != nil || got == nil || got.AID != "EWithFTS" {
		t.Fatalf("nothing else was restored: %+v %v", got, err)
	}
	// And the searchable content came across.
	var body string
	if err := into.db.QueryRow(
		`SELECT body FROM downstream_fts WHERE downstream_fts MATCH 'findable'`).Scan(&body); err != nil {
		t.Fatalf("the virtual table came back empty: %v", err)
	}
}

// A unique index is not decoration — without it the restored database quietly
// starts accepting duplicates. Indexes, triggers and views are separate rows
// in sqlite_master, so copying only tables left them behind.
func TestAUniqueIndexSurvivesTheRestore(t *testing.T) {
	_, from := openStore(t)
	if _, err := from.db.Exec(
		`CREATE TABLE downstream_notes (id TEXT PRIMARY KEY, slug TEXT);
		 CREATE UNIQUE INDEX downstream_notes_slug ON downstream_notes(slug);
		 CREATE VIEW downstream_recent AS SELECT id FROM downstream_notes;`); err != nil {
		t.Fatal(err)
	}
	if _, err := from.db.Exec(
		`INSERT INTO downstream_notes VALUES ('n1', 'only-once')`); err != nil {
		t.Fatal(err)
	}
	snap := snapshotOf(t, from)

	_, into := openStore(t)
	if err := into.ImportSnapshot(snap); err != nil {
		t.Fatal(err)
	}
	if _, err := into.db.Exec(
		`INSERT INTO downstream_notes VALUES ('n2', 'only-once')`); err == nil {
		t.Fatal("the unique index was lost — the restored database accepts duplicates")
	}
	if _, err := into.db.Exec(`SELECT 1 FROM downstream_recent`); err != nil {
		t.Fatalf("the view was lost: %v", err)
	}
}

// A table the backup left empty must not clear the one here.
//
// Tables with nothing to match rows on are replaced rather than added to, or
// every restore appends another copy of every row. But clearing first and then
// copying nothing deletes what is here and puts nothing back — and profile and
// endpoint have no parsed section to repair it, so an ordinary successful
// restore from a machine that never set a profile wiped the local one.
func TestARestoreDoesNotEmptyATableTheBackupNeverFilled(t *testing.T) {
	_, from := openStore(t)
	snap := snapshotOf(t, from) // never had a profile set

	_, into := openStore(t)
	if err := into.SaveProfile(ProfileData{FullName: "Mine, from this machine"}); err != nil {
		t.Fatal(err)
	}
	if err := into.ImportSnapshot(snap); err != nil {
		t.Fatal(err)
	}

	got, err := into.GetProfile()
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.FullName != "Mine, from this machine" {
		t.Fatalf("the local profile was deleted and nothing put back: %+v", got)
	}
}

// An ordinary table must not be mistaken for part of a virtual table.
//
// A virtual table stores itself in several ordinary-looking tables. Guessing
// which those are from a name prefix swallows any real table that happens to
// share it: with a virtual table `notes`, a downstream `notes_archive` is not
// part of it, and treating it as one loses the table completely and silently —
// exactly the data this change exists to preserve.
func TestATableThatMerelySharesAVirtualTablesNameSurvives(t *testing.T) {
	_, from := openStore(t)
	if _, err := from.db.Exec(`CREATE VIRTUAL TABLE notes USING fts5(body)`); err != nil {
		t.Skipf("this build has no FTS5: %v", err)
	}
	if _, err := from.db.Exec(
		`CREATE TABLE notes_archive (id TEXT PRIMARY KEY, body TEXT);
		 INSERT INTO notes_archive VALUES ('a1', 'kept somewhere else')`); err != nil {
		t.Fatal(err)
	}
	snap := snapshotOf(t, from)

	_, into := openStore(t)
	if err := into.ImportSnapshot(snap); err != nil {
		t.Fatal(err)
	}
	var body string
	if err := into.db.QueryRow(
		`SELECT body FROM notes_archive WHERE id='a1'`).Scan(&body); err != nil {
		t.Fatalf("notes_archive did not survive the restore: %v", err)
	}

	// The other direction, so this cannot be satisfied by finding no internal
	// tables at all: the virtual table's own content must still come back.
	if _, err := into.db.Exec(
		`INSERT INTO notes (body) VALUES ('afterwards')`); err != nil {
		t.Fatalf("the virtual table is unusable after the restore: %v", err)
	}
	if _, err := into.db.Exec(`INSERT INTO notes(notes) VALUES('integrity-check')`); err != nil {
		t.Fatalf("the restored index does not pass its own integrity check: %v", err)
	}
}

// A table is virtual or not according to SQLite, not according to its text.
//
// Searching the DDL for "CREATE VIRTUAL TABLE" misreads any ordinary table
// that merely mentions the phrase — in a default value, a check constraint or
// a comment. A table classified virtual is never copied, so its schema arrives
// and its rows do not.
func TestATableThatMentionsVirtualTablesIsStillCopied(t *testing.T) {
	_, from := openStore(t)
	if _, err := from.db.Exec(
		`CREATE TABLE downstream_docs (
		   id TEXT PRIMARY KEY,
		   body TEXT DEFAULT 'run: create virtual table foo using fts5(x)');
		 INSERT INTO downstream_docs (id, body) VALUES ('d1', 'the actual row');`); err != nil {
		t.Fatal(err)
	}
	snap := snapshotOf(t, from)

	_, into := openStore(t)
	if err := into.ImportSnapshot(snap); err != nil {
		t.Fatal(err)
	}
	var body string
	if err := into.db.QueryRow(
		`SELECT body FROM downstream_docs WHERE id='d1'`).Scan(&body); err != nil {
		t.Fatalf("the row was never copied: %v", err)
	}
	if body != "the actual row" {
		t.Fatalf("it came back wrong: %q", body)
	}
}

// A database that is not an identity database is refused rather than merged.
//
// Treating "no schema history" as version zero makes an unrelated SQLite file
// indistinguishable from an old backup, and it is then merged into the
// identity store wholesale without complaint. The archive is opened with the
// owner's own key so this is not an attack, but it is the last chance to catch
// a mis-assembled archive.
func TestSomethingThatIsNotAnIdentityDatabaseIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shopping.db")
	other, err := sqlOpenForTest(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Exec(
		`CREATE TABLE item (name TEXT); INSERT INTO item VALUES ('milk')`); err != nil {
		t.Fatal(err)
	}
	other.Close()

	_, into := openStore(t)
	err = into.ImportSnapshot(path)
	if err == nil {
		t.Fatal("a database that is not an identity database was merged in wholesale")
	}
	if !strings.Contains(err.Error(), "identity database") {
		t.Fatalf("the refusal does not explain itself: %v", err)
	}
}

func sqlOpenForTest(path string) (*sql.DB, error) {
	return sql.Open("sqlite", path)
}

// Restoring a virtual table over one that already has content must not
// interleave the two.
//
// A virtual table stores itself in tables keyed by row ids that mean nothing
// outside it. Merging two of them with INSERT OR REPLACE puts the backup's
// rows on top of local rows that happen to share ids, producing an index that
// is neither — and fts5's own integrity check still passes, so the loss is
// silent. Those tables are replaced wholesale instead.
func TestRestoringAVirtualTableOverAnExistingOneDoesNotLoseRows(t *testing.T) {
	_, from := openStore(t)
	if _, err := from.db.Exec(`CREATE VIRTUAL TABLE notes USING fts5(body)`); err != nil {
		t.Skipf("this build has no FTS5: %v", err)
	}
	// Deliberately fewer than the local index holds. Equal counts make the
	// backup's row ids overwrite the local ones exactly, so merging and
	// replacing produce the same answer and the test proves nothing — which is
	// what an earlier version of it did.
	for i := 0; i < 40; i++ {
		if _, err := from.db.Exec(
			`INSERT INTO notes (body) VALUES (?)`, fmt.Sprintf("backedup%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	snap := snapshotOf(t, from)

	// The receiving machine has its own, independently built index.
	_, into := openStore(t)
	if _, err := into.db.Exec(`CREATE VIRTUAL TABLE notes USING fts5(body)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 400; i++ {
		if _, err := into.db.Exec(
			`INSERT INTO notes (body) VALUES (?)`, fmt.Sprintf("localonly%d", i)); err != nil {
			t.Fatal(err)
		}
	}

	if err := into.ImportSnapshot(snap); err != nil {
		t.Fatal(err)
	}

	var backedUp int
	if err := into.db.QueryRow(
		`SELECT count(*) FROM notes WHERE notes MATCH 'backedup*'`).Scan(&backedUp); err != nil {
		t.Fatalf("the restored index is unusable: %v", err)
	}
	if backedUp != 40 {
		t.Fatalf("the backup's index came back with %d of 40 entries", backedUp)
	}
	// And it is coherent rather than two indexes stirred together.
	if _, err := into.db.Exec(`INSERT INTO notes(notes) VALUES('integrity-check')`); err != nil {
		t.Fatalf("the restored index does not pass its own integrity check: %v", err)
	}
}

// Schema text carried by a backup is executed against the live database, so it
// must be one statement creating one thing.
//
// sqlite_master.sql is normally exactly what SQLite recorded, but
// PRAGMA writable_schema lets it be anything. The restore replaced "write
// bytes over a file" with "execute the artifact's schema", which is a surface
// that did not exist before — a second statement behind a semicolon runs with
// the restore's own access. The archive is opened with the owner's key so this
// is not a remote attack; it is containment for something that has been off
// this machine.
func TestSchemaTextCarryingASecondStatementIsRefused(t *testing.T) {
	// Built as a file rather than through VACUUM INTO, deliberately. VACUUM
	// rewrites sqlite_master from the parsed schema, so it launders tampering
	// — which means a backup this agent took is safe by construction. The
	// bytes in an archive are not: an archive is an artifact that has been off
	// this machine, and the restore reads whatever the section contains.
	dir := t.TempDir()
	path := filepath.Join(dir, "tampered.db")
	raw, err := sqlOpenForTest(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyMigrationsUpTo(raw, newestKnownMigration()); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE downstream_thing (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`PRAGMA writable_schema=ON`); err != nil {
		t.Skipf("this build will not allow the schema to be rewritten: %v", err)
	}
	if _, err := raw.Exec(
		`UPDATE sqlite_master
		    SET sql = 'CREATE TABLE downstream_thing (id TEXT PRIMARY KEY); DELETE FROM contacts'
		  WHERE name = 'downstream_thing'`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	_, into := openStore(t)
	if err := into.SaveContact(ContactRecord{AID: "EStillHere", Alias: "Still here"}); err != nil {
		t.Fatal(err)
	}

	err = into.ImportSnapshot(path)
	if err == nil {
		t.Fatal("schema text carrying a second statement was executed")
	}
	if !strings.Contains(err.Error(), "more than one statement") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}

	contacts, err := into.GetContacts()
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 1 {
		t.Fatal("the smuggled statement ran against the live identity database")
	}
}

// A child row copied before its parent must not fail the restore.
//
// Tables are copied in whatever order sqlite_master lists them, so a row can
// legitimately arrive before the row it refers to. Enforcement goes off for
// the copy, and back to whatever this connection had — not unconditionally on,
// which would newly enable it on a connection that did not have it and make
// later writes checked or unchecked depending on which one the pool serves.
func TestAChildRowCopiedBeforeItsParentStillRestores(t *testing.T) {
	_, from := openStore(t)
	if _, err := from.db.Exec(
		// The child is created FIRST, so sqlite_master lists it first and the
		// copy reaches it before the parent exists. Created the other way round
		// there is no violation to enforce and the test proves nothing.
		`CREATE TABLE aa_child (id TEXT PRIMARY KEY,
		   parent TEXT NOT NULL REFERENCES zz_parent(id));
		 CREATE TABLE zz_parent (id TEXT PRIMARY KEY);
		 INSERT INTO zz_parent VALUES ('p1');
		 INSERT INTO aa_child VALUES ('c1', 'p1');`); err != nil {
		t.Fatal(err)
	}
	snap := snapshotOf(t, from)

	_, into := openStore(t)
	if err := into.ImportSnapshot(snap); err != nil {
		t.Fatalf("a child row copied before its parent failed the restore: %v", err)
	}
	var parent string
	if err := into.db.QueryRow(`SELECT parent FROM aa_child WHERE id='c1'`).Scan(&parent); err != nil {
		t.Fatal(err)
	}
	if parent != "p1" {
		t.Fatalf("the child row came back wrong: %q", parent)
	}
}

// A downstream table with no primary key is left alone, not cleared.
//
// Clearing is right for this schema's four single-row tables. It is wrong for
// a table this core has never heard of: an append-only log or an audit trail
// written on this machine since the backup would be deleted. Duplicating rows
// is recoverable in a way that deleting them is not.
func TestADownstreamTableWithNoPrimaryKeyIsNotCleared(t *testing.T) {
	_, from := openStore(t)
	if _, err := from.db.Exec(
		`CREATE TABLE downstream_log (line TEXT);
		 INSERT INTO downstream_log VALUES ('from the backup')`); err != nil {
		t.Fatal(err)
	}
	snap := snapshotOf(t, from)

	_, into := openStore(t)
	if _, err := into.db.Exec(
		`CREATE TABLE downstream_log (line TEXT);
		 INSERT INTO downstream_log VALUES ('written on this machine since')`); err != nil {
		t.Fatal(err)
	}
	if err := into.ImportSnapshot(snap); err != nil {
		t.Fatal(err)
	}

	var kept int
	if err := into.db.QueryRow(
		`SELECT count(*) FROM downstream_log WHERE line='written on this machine since'`).
		Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if kept != 1 {
		t.Fatal("a downstream table written since the backup was cleared by the restore")
	}
}
