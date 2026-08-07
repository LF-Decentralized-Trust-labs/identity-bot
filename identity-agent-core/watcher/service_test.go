package watcher

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"identity-agent-core/store"

	_ "modernc.org/sqlite"
)

func TestVerifyKelFirstContactAndRepeat(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.ApplyIdentityMigrations(db); err != nil {
		t.Fatal(err)
	}
	applyWatcherTables(t, db)

	ws := NewService(NewSQLiteStore(db))
	kel := []map[string]interface{}{
		{"v": "KERI10JSON000256_", "t": "icp", "i": "EBob", "s": "0"},
	}

	// First contact — L2 unavailable in test, should confirm via L1 only path
	res, err := ws.VerifyKel(context.Background(), VerifyKelInput{
		AID: "EBob", KEL: kel, SourceType: SourceOOBI, SourceURL: "http://test/oobi",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Blocked {
		t.Fatalf("first contact: ok=%v blocked=%v reason=%s", res.OK, res.Blocked, res.Reason)
	}

	// Repeat — same digest reinforces
	res2, err := ws.VerifyKel(context.Background(), VerifyKelInput{
		AID: "EBob", KEL: kel, SourceType: SourceOOBI,
	})
	if err != nil || !res2.OK {
		t.Fatalf("repeat verify failed: %v %+v", err, res2)
	}

	// Forked KEL at same seq — different event body
	forked := []map[string]interface{}{
		{"v": "KERI10JSON000256_", "t": "icp", "i": "EBob", "s": "0", "k": []string{"Dfork"}},
	}
	res3, err := ws.VerifyKel(context.Background(), VerifyKelInput{
		AID: "EBob", KEL: forked, SourceType: SourceCredential,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res3.Blocked {
		t.Fatal("expected block on L1 mismatch")
	}
}

func TestPublicDigestAndKelCheck(t *testing.T) {
	dir := t.TempDir()
	db, _ := sql.Open("sqlite", filepath.Join(dir, "w.db"))
	defer db.Close()
	applyWatcherTables(t, db)
	ws := NewService(NewSQLiteStore(db))
	now := time.Now().UTC()
	_ = ws.Store.RecordFirstSeen(FirstSeenRecord{
		AID: "EAlice", SequenceNum: 2, KelDigest: "Edigest123",
		FirstSeenAt: now, LastConfirmedAt: now, SeenCount: 1,
		SourceType: SourceOOBI,
	})

	resp, err := ws.GetPublicDigest("EAlice", 2)
	if err != nil || resp.Digest == nil || *resp.Digest != "Edigest123" {
		t.Fatalf("GetPublicDigest: %+v err=%v", resp, err)
	}

	check, err := ws.KelCheck(KelCheckRequest{AID: "EAlice", Seq: 2, Digest: "Edigest123"})
	if err != nil || !check.Match {
		t.Fatalf("KelCheck match: %+v", check)
	}
	check2, _ := ws.KelCheck(KelCheckRequest{AID: "EAlice", Seq: 2, Digest: "Ewrong"})
	if check2.Match {
		t.Fatal("expected mismatch")
	}
}

func applyWatcherTables(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS kel_first_seen (
    aid TEXT NOT NULL, sequence_num INTEGER NOT NULL, kel_digest TEXT NOT NULL,
    first_seen_at TEXT NOT NULL, last_confirmed_at TEXT NOT NULL,
    seen_count INTEGER DEFAULT 1, source_type TEXT NOT NULL, source_url TEXT,
    PRIMARY KEY (aid, sequence_num)
);
CREATE TABLE IF NOT EXISTS duplicity_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, aid TEXT NOT NULL, sequence_num INTEGER NOT NULL,
    our_digest TEXT NOT NULL, their_digest TEXT NOT NULL, source_url TEXT,
    detected_at TEXT NOT NULL, resolved INTEGER DEFAULT 0, resolution_note TEXT
);
CREATE TABLE IF NOT EXISTS watcher_opt_out (aid TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS watcher_config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`)
	if err != nil {
		t.Fatal(err)
	}
}
