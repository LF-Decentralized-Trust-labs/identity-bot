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
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(`
CREATE TABLE contacts (aid TEXT PRIMARY KEY, contact_source TEXT DEFAULT 'manual');
CREATE TABLE IF NOT EXISTS witness_contact_meta (
    contact_aid TEXT PRIMARY KEY, backend_type TEXT, witness_status TEXT DEFAULT 'online',
    offline_count INTEGER DEFAULT 0, is_mutual INTEGER DEFAULT 0, is_commercial INTEGER DEFAULT 0,
    witnessing_for INTEGER DEFAULT 0,
    enrolled_at TEXT, last_receipt_at TEXT, last_health_check TEXT);
CREATE TABLE IF NOT EXISTS witness_kel_events (
    signer_aid TEXT, sequence_num INTEGER, event_json TEXT, event_said TEXT, stored_at TEXT,
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
