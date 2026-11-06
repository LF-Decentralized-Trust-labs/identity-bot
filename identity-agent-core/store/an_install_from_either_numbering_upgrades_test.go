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

func hasTable(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name = ?`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func requireFullyMigrated(t *testing.T, db *sql.DB) {
	t.Helper()
	got := versionsRecorded(t, db)
	if len(got) != len(identityMigrations) {
		t.Errorf("%d migrations recorded, want %d", len(got), len(identityMigrations))
	}
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
	for _, table := range []string{"witness_tel_events", "tel_push_outbox", "tel_backfill", "tel_push_retry"} {
		if !hasTable(t, db, table) {
			t.Errorf("%s (migrations 47 to 50) was never created", table)
		}
	}
	if !hasIndex(t, db, "idx_kel_superseded_aid") || !hasIndex(t, db, "idx_witness_kel_superseded_aid") {
		t.Error("the superseded-event tables are missing")
	}
}

// An install that ran main's migrations to 50 runs the signature migrations,
// now 51 and 52.
func TestAnInstallThatRanMainsMigrationsRunsTheSignatureMigrations(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "id.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := applyMigrationsUpTo(db, 50); err != nil {
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

// An install from before main's migrations landed ran the signature
// migrations under the numbers they had then: 46 and 47 on one that never ran
// main's 46, 47 and 48 on one that did. Either must upgrade without failing,
// without being left short of any of main's migrations, and without running a
// signature migration a second time, whether it ran one of them or both.
func TestAnInstallThatRanTheSignatureMigrationsUnderEarlierNumbersStillUpgrades(t *testing.T) {
	for _, numbering := range []struct {
		name    string
		upTo    int
		numbers [2]int
	}{
		{"before main's 46", 45, [2]int{46, 47}},
		{"before main's 47 to 50", 46, [2]int{47, 48}},
	} {
		for _, ranBoth := range []bool{true, false} {
			db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "id.db"))
			if err != nil {
				t.Fatal(err)
			}
			if err := applyMigrationsUpTo(db, numbering.upTo); err != nil {
				t.Fatal(err)
			}
			for i, now := range []int{51, 52} {
				if i == 1 && !ranBoth {
					break
				}
				q, d := migrationSQL(t, now)
				if _, err := db.Exec(q); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`INSERT INTO identity_schema_migrations (version, description, applied_at)
					VALUES (?, ?, '2026-01-01')`, numbering.numbers[i], d); err != nil {
					t.Fatal(err)
				}
			}
			if hasTable(t, db, "witness_tel_events") {
				t.Fatal("the install under test already has main's 47")
			}
			// An early migration recorded under the wording it had then: its
			// number says it ran, and running it again would fail.
			if _, err := db.Exec(`UPDATE identity_schema_migrations SET description = 'an earlier wording' WHERE version = 2`); err != nil {
				t.Fatal(err)
			}
			if err := ApplyIdentityMigrations(db); err != nil {
				t.Fatalf("%s, ranBoth=%v: %v", numbering.name, ranBoth, err)
			}
			var applied string
			if err := db.QueryRow(`SELECT applied_at FROM identity_schema_migrations WHERE version = 51`).Scan(&applied); err != nil || applied != "2026-01-01" {
				t.Errorf("%s: the moved record was rewritten, not moved (applied_at %q, %v)", numbering.name, applied, err)
			}
			if _, err := db.Exec(`UPDATE identity_schema_migrations SET description = ? WHERE version = 2`, mustDescription(t, 2)); err != nil {
				t.Fatal(err)
			}
			requireFullyMigrated(t, db)
			// And a second start finds nothing to do.
			if err := ApplyIdentityMigrations(db); err != nil {
				t.Fatalf("%s, second start: %v", numbering.name, err)
			}
			db.Close()
		}
	}
}

func mustDescription(t *testing.T, version int) string {
	t.Helper()
	_, d := migrationSQL(t, version)
	return d
}
