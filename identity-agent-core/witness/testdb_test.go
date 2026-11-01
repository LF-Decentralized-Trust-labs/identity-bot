package witness

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"identity-agent-core/store"
)

func setupTestSQLite(t *testing.T) Store {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	// ONE CONNECTION, and this is not a tuning choice.
	//
	// sql.DB is a pool, and an in-memory SQLite database belongs to the
	// CONNECTION rather than to the process. So the moment the pool opens a
	// second one, that connection gets its own empty database: the tables are
	// not there, and a row written a line earlier reads back as missing.
	//
	// The symptom is not a clear failure. GetContactMeta reports no row as
	// (nil, nil) — correct, since absent is a real answer — so a caller that
	// discards the error dereferences nil and the whole test binary panics.
	// That took the package down about one run in eight, which read as a
	// witness bug and was reported as one on several pull requests.
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	// The schema the agent's own migrations build, so the witness's tables
	// here never drift from the ones it runs on.
	err = store.ApplyIdentityMigrations(db)
	if err != nil {
		t.Fatal(err)
	}
	return NewSQLiteStore(db)
}
