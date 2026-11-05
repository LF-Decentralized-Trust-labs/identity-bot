package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func versionsRecorded(t *testing.T, db *sql.DB) map[int]string {
	t.Helper()
	rows, err := db.Query(`SELECT version, description FROM identity_schema_migrations`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[int]string{}
	for rows.Next() {
		var v int
		var d string
		if err := rows.Scan(&v, &d); err != nil {
			t.Fatal(err)
		}
		out[v] = d
	}
	return out
}

func hasColumn(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func hasIndex(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name = ?`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func migrationSQL(t *testing.T, version int) (string, string) {
	t.Helper()
	for _, m := range identityMigrations {
		if m.Version == version {
			return m.SQL, m.Description
		}
	}
	t.Fatalf("no migration %d", version)
	return "", ""
}

func requireFullyMigrated(t *testing.T, db *sql.DB) {
	t.Helper()
	got := versionsRecorded(t, db)
	for _, m := range identityMigrations {
		if got[m.Version] != m.Description {
			t.Errorf("migration %d recorded as %q, want %q", m.Version, got[m.Version], m.Description)
		}
	}
	if !hasColumn(t, db, "kel", "signatures") || !hasColumn(t, db, "witness_kel_events", "signatures") {
		t.Error("the signature columns are missing")
	}
	if !hasIndex(t, db, "idx_duplicity_alerts_identity") {
		t.Error("the counter-identity indexes (migration 46) were never applied")
	}
	if !hasIndex(t, db, "idx_kel_superseded_aid") || !hasIndex(t, db, "idx_witness_kel_superseded_aid") {
		t.Error("the superseded-event tables are missing")
	}
}

// An install that ran main's migration 46 runs this branch's two, now 47 and 48.
func TestAnInstallThatRanMainsMigration46RunsTheSignatureMigrations(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "id.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := applyMigrationsUpTo(db, 46); err != nil {
		t.Fatal(err)
	}
	if hasColumn(t, db, "kel", "signatures") {
		t.Fatal("the install under test already has a later migration")
	}
	if err := ApplyIdentityMigrations(db); err != nil {
		t.Fatal(err)
	}
	requireFullyMigrated(t, db)
}

// An install from this branch ran the signature migrations as 46 and 47 and
// never ran main's 46. It must not fail, must not be left without main's 46,
// and must not run the witness migration a second time.
func TestAnInstallFromThisBranchBeforeRenumberingStillUpgrades(t *testing.T) {
	for _, ranBoth := range []bool{true, false} {
		db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "id.db"))
		if err != nil {
			t.Fatal(err)
		}
		if err := applyMigrationsUpTo(db, 45); err != nil {
			t.Fatal(err)
		}
		// What the branch ran, under the numbers it had then.
		old := map[int]int{47: 46, 48: 47}
		for _, nw := range []int{47, 48} {
			if nw == 48 && !ranBoth {
				break
			}
			q, d := migrationSQL(t, nw)
			if _, err := db.Exec(q); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO identity_schema_migrations (version, description, applied_at)
				VALUES (?, ?, '2026-01-01')`, old[nw], d); err != nil {
				t.Fatal(err)
			}
		}
		if hasIndex(t, db, "idx_duplicity_alerts_identity") {
			t.Fatal("the install under test already has main's 46")
		}
		if err := ApplyIdentityMigrations(db); err != nil {
			t.Fatalf("ranBoth=%v: %v", ranBoth, err)
		}
		requireFullyMigrated(t, db)
		// And a second start finds nothing to do.
		if err := ApplyIdentityMigrations(db); err != nil {
			t.Fatalf("second start: %v", err)
		}
		db.Close()
	}
}
