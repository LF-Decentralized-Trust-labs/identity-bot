package witness

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
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
	_, err = db.Exec(`
CREATE TABLE contacts (aid TEXT PRIMARY KEY, contact_source TEXT DEFAULT 'manual');
CREATE TABLE IF NOT EXISTS witness_contact_meta (
    contact_aid TEXT PRIMARY KEY, backend_type TEXT, witness_status TEXT DEFAULT 'online',
    offline_count INTEGER DEFAULT 0, is_mutual INTEGER DEFAULT 0, is_commercial INTEGER DEFAULT 0,
    witnessing_for INTEGER DEFAULT 0, witness_key TEXT NOT NULL DEFAULT '',
    entity_type TEXT NOT NULL DEFAULT '',
    enrolled_at TEXT, last_receipt_at TEXT, last_health_check TEXT);
CREATE TABLE IF NOT EXISTS witness_kel_events (
    signer_aid TEXT, sequence_num INTEGER, event_json TEXT, event_said TEXT, stored_at TEXT,
    raw_bytes_b64 TEXT NOT NULL DEFAULT '', cesr_signature TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (signer_aid, sequence_num));
CREATE TABLE IF NOT EXISTS witness_receipts_issued (
    id INTEGER PRIMARY KEY AUTOINCREMENT, signer_aid TEXT, event_said TEXT, sequence_num INTEGER,
    witness_aid TEXT, receipt_json TEXT, cesr_signature TEXT, issued_at TEXT);
CREATE TABLE IF NOT EXISTS witness_finalization (
    event_said TEXT PRIMARY KEY, signer_aid TEXT, sequence_num INTEGER, state TEXT,
    receipt_count INTEGER, threshold INTEGER, started_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS witness_config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS witness_self_heal_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, contact_aid TEXT, attempted_at TEXT);
`)
	if err != nil {
		t.Fatal(err)
	}
	return NewSQLiteStore(db)
}
