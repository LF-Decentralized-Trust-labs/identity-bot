package store

import (
	"database/sql"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Migrations numbered from everyUnrecordedMigrationRunsFrom up, standing in for
// ones not written yet. Each notes in migration_runs that it ran, so a test can
// count how often it did. Each but the first creates a table, so running one a
// second time would also fail.
const (
	runLog     = 9000
	lowerLate  = 9001
	higherLate = 9002
)

var laterMigrations = map[int]string{
	runLog: `CREATE TABLE migration_runs (version INTEGER NOT NULL);
INSERT INTO migration_runs (version) VALUES (9000);`,
	lowerLate: `CREATE TABLE lower_late (id INTEGER PRIMARY KEY);
INSERT INTO migration_runs (version) VALUES (9001);`,
	higherLate: `CREATE TABLE higher_late (id INTEGER PRIMARY KEY);
INSERT INTO migration_runs (version) VALUES (9002);`,
}

// listMigrations makes this build list its own migrations followed by the
// given later ones, in that order, until the test ends. A later call replaces
// the later ones an earlier call listed.
func listMigrations(t *testing.T, versions ...int) {
	t.Helper()
	if versions[0] < everyUnrecordedMigrationRunsFrom {
		t.Fatal("a later migration must be numbered from the floor up")
	}
	real := identityMigrations
	t.Cleanup(func() { identityMigrations = real })
	list := slices.DeleteFunc(slices.Clone(real), func(m struct {
		Version     int
		Description string
		SQL         string
	}) bool {
		_, later := laterMigrations[m.Version]
		return later
	})
	for _, v := range versions {
		list = append(list, struct {
			Version     int
			Description string
			SQL         string
		}{v, "a later migration", laterMigrations[v]})
	}
	identityMigrations = list
}

func timesRun(t *testing.T, db *sql.DB, version int) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM migration_runs WHERE version = ?`, version).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func freshDatabase(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "id.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestAMigrationNumberedBelowOneAlreadyRecordedStillRunsWhenItLandsLater(t *testing.T) {
	db := freshDatabase(t)
	listMigrations(t, runLog, higherLate)
	if err := ApplyIdentityMigrations(db); err != nil {
		t.Fatal(err)
	}

	// The lower number lands after the higher one has run here.
	listMigrations(t, runLog, lowerLate, higherLate)
	for range 2 {
		if err := ApplyIdentityMigrations(db); err != nil {
			t.Fatal(err)
		}
	}
	if n := timesRun(t, db, lowerLate); n != 1 {
		t.Fatalf("the migration that landed late ran %d times, want once", n)
	}
	if n := timesRun(t, db, higherLate); n != 1 {
		t.Fatalf("the migration already recorded ran %d times, want once", n)
	}
	requireFullyMigrated(t, db)
}

// A database from before this rule can lack the record of a migration below
// the floor that did run: renumberBranchMigrations describes installs whose
// records sat under other numbers. Its highest number still says that
// migration is done, and running it again would fail.
func TestADatabaseFromBeforeThisRuleReRunsNothing(t *testing.T) {
	db := freshDatabase(t)
	if err := applyMigrationsUpTo(db, everyUnrecordedMigrationRunsFrom-1); err != nil {
		t.Fatal(err)
	}
	// Migration 34 renames a column, so it cannot run twice.
	if _, err := db.Exec(`DELETE FROM identity_schema_migrations WHERE version = ?`, renameOfDelegatedAID); err != nil {
		t.Fatal(err)
	}
	if err := ApplyIdentityMigrations(db); err != nil {
		t.Fatalf("a migration below the floor ran again: %v", err)
	}
	if _, ran := versionsRecorded(t, db)[renameOfDelegatedAID]; ran {
		t.Fatal("a migration below the floor that had no record was recorded as run now")
	}
}

func TestAMigrationRecordedAsAppliedNeverRunsTwice(t *testing.T) {
	db := freshDatabase(t)
	listMigrations(t, runLog, lowerLate, higherLate)
	if err := ApplyIdentityMigrations(db); err != nil {
		t.Fatal(err)
	}
	// The higher one's record goes, so the highest number recorded is now
	// below a migration that is recorded and must still be left alone.
	if _, err := db.Exec(`DELETE FROM identity_schema_migrations WHERE version = ?`, higherLate); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE higher_late`); err != nil {
		t.Fatal(err)
	}
	if err := ApplyIdentityMigrations(db); err != nil {
		t.Fatalf("a recorded migration ran again: %v", err)
	}
	for _, v := range []int{runLog, lowerLate} {
		if n := timesRun(t, db, v); n != 1 {
			t.Fatalf("recorded migration %d ran %d times, want once", v, n)
		}
	}
	if n := timesRun(t, db, higherLate); n != 2 {
		t.Fatalf("the migration with no record ran %d times in all, want twice", n)
	}
}

func TestARestoredBackupRunsWhatItHasNotRunAndNothingElse(t *testing.T) {
	// The backup was made by a build that had the higher migration and not
	// yet the lower one.
	listMigrations(t, runLog, higherLate)
	_, from := openStore(t)
	snap := snapshotOf(t, from)

	listMigrations(t, runLog, lowerLate, higherLate)
	_, into := openStore(t)
	if err := into.ImportSnapshot(snap); err != nil {
		t.Fatal(err)
	}
	// The restore brings the backup forward in place, so the backup itself
	// says what ran on it, before and during the restore.
	backup, err := sql.Open("sqlite", snap)
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	for _, v := range []int{runLog, lowerLate, higherLate} {
		if n := timesRun(t, backup, v); n != 1 {
			t.Fatalf("migration %d ran %d times on the backup, want once", v, n)
		}
	}
	requireFullyMigrated(t, backup)
	requireFullyMigrated(t, into.db)
}

// The highest number a backup records being one this build knows does not make
// the backup no newer than this build: it may have run a migration that landed
// out of order and this build lacks.
func TestABackupThatRanAMigrationThisBuildLacksIsRefused(t *testing.T) {
	listMigrations(t, runLog, lowerLate, higherLate)
	_, from := openStore(t)
	snap := snapshotOf(t, from)

	listMigrations(t, runLog, higherLate)
	_, into := openStore(t)
	err := into.ImportSnapshot(snap)
	if err == nil {
		t.Fatal("a backup that ran a migration this build lacks was accepted")
	}
	for _, want := range []string{"newer version", "update the software"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not explain itself: %q", err)
		}
	}
	if hasTable(t, into.db, "lower_late") {
		t.Fatal("the refused backup was merged anyway")
	}
}
