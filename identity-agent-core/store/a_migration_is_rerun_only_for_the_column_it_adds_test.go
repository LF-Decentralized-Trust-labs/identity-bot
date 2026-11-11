package store

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func scratchDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE t (a TEXT, b TEXT)`); err != nil {
		t.Fatal(err)
	}
	return db
}

// Running the one ADD COLUMN again is fine.
func TestAnAddColumnMigrationRunAgainIsAccepted(t *testing.T) {
	db := scratchDB(t)
	body := "-- note\nALTER TABLE t ADD COLUMN c TEXT NOT NULL DEFAULT 'x';\n"
	if err := execMigration(db, body); err != nil {
		t.Fatal(err)
	}
	if err := execMigration(db, body); err != nil {
		t.Fatalf("the same ADD COLUMN again: %v", err)
	}
}

// A different statement, or a different column's error, still surfaces: a
// RENAME COLUMN must not be recorded as applied because the target name exists.
func TestAMigrationThatIsNotThatAddColumnKeepsItsError(t *testing.T) {
	db := scratchDB(t)
	if err := execMigration(db, "ALTER TABLE t RENAME COLUMN a TO b;"); err == nil {
		t.Fatal("a RENAME COLUMN onto an existing column was accepted")
	}
	if err := execMigration(db, "ALTER TABLE t ADD COLUMN c TEXT; ALTER TABLE t ADD COLUMN a TEXT;"); err == nil {
		t.Fatal("two statements were accepted")
	}
	if _, ok := oneAddColumn("ALTER TABLE t RENAME COLUMN a TO b;"); ok {
		t.Fatal("RENAME COLUMN read as ADD COLUMN")
	}
}

type fakeExec struct{ err error }

func (f fakeExec) Exec(string, ...any) (sql.Result, error) { return nil, f.err }

func TestADuplicateColumnErrorNamingAnotherColumnSurfaces(t *testing.T) {
	err := execMigration(fakeExec{errString("duplicate column name: other")}, "ALTER TABLE t ADD COLUMN c TEXT;")
	if err == nil {
		t.Fatal("another column's duplicate error was swallowed")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
