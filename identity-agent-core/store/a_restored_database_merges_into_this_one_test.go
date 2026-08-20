package store

import (
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

// The receiving database must end up at the version its own binary expects,
// having actually run the migrations rather than recording them as run.
func TestARestoredDatabaseIsMigratedNotJustMarked(t *testing.T) {
	_, from := openStore(t)
	if err := from.SaveIdentity(IdentityState{
		AID: "EOld", PublicKey: "dGVzdA==", NextKeyDigest: "d",
		Created: "2026-01-01T00:00:00Z", EventCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	// A backup that predates every migration this build knows about.
	if _, err := from.db.Exec(`DELETE FROM identity_schema_migrations WHERE version > 1`); err != nil {
		t.Fatal(err)
	}
	snap := snapshotOf(t, from)

	_, into := openStore(t)
	if err := into.ImportSnapshot(snap); err != nil {
		t.Fatal(err)
	}

	var version int
	if err := into.db.QueryRow(
		`SELECT COALESCE(MAX(version), 0) FROM identity_schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != newestKnownMigration() {
		t.Fatalf("schema left at version %d, this build expects %d", version, newestKnownMigration())
	}
	// The store still works, which is what a wedged schema breaks.
	if err := into.SaveEvent(EventRecord{
		AID: "EOld", EventType: "icp", SequenceNumber: 0,
		EventJSON: "{}", Timestamp: "2026-01-01T00:00:00Z",
	}); err != nil {
		t.Fatalf("the store is unusable after the restore: %v", err)
	}
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
