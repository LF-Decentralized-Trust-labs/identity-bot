package store

import (
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// An install that holds guardianships from the delegation era upgrades: the
// dependent's identifier, name and status stay, the guardian identifiers go.
func TestTheDelegationColumnsAreDroppedAndTheDependentIsKept(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	for _, m := range identityMigrations {
		if m.Version > 58 {
			break
		}
		if m.Version != 8 && m.Version != 10 {
			continue
		}
		if err := execMigration(db, m.SQL); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO guardianships (id, type, guardian_aid, dependent_aid, dependent_name, delegated_aid_prefix, co_guardians_json, multisig_threshold, credential_said)
		VALUES ('g','minor_child','EGuardian','EDep','Sam','EDelegated','["EOther"]',2,'ECred')`); err != nil {
		t.Fatal(err)
	}
	var m59 string
	for _, m := range identityMigrations {
		if m.Version == 59 {
			m59 = m.SQL
		}
	}
	if m59 == "" {
		t.Fatal("no migration 59")
	}
	if err := execMigration(db, m59); err != nil {
		t.Fatal(err)
	}
	var dep, name, cred, parts string
	var th int
	if err := db.QueryRow(`SELECT dependent_aid, dependent_name, credential_said, multisig_participants_json, multisig_threshold FROM guardianships WHERE id='g'`).Scan(&dep, &name, &cred, &parts, &th); err != nil {
		t.Fatal(err)
	}
	if dep != "EDep" || name != "Sam" || cred != "ECred" || th != 2 || parts != "[]" {
		t.Errorf("kept %q %q %q %q %d", dep, name, cred, parts, th)
	}
	rows, _ := db.Query(`SELECT name FROM pragma_table_info('guardianships')`)
	for rows.Next() {
		var c string
		_ = rows.Scan(&c)
		if strings.Contains(c, "guardian_aid") || strings.Contains(c, "delegated") || c == "co_guardians_json" {
			t.Errorf("column %s remains", c)
		}
	}
}
