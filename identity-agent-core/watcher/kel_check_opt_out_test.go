package watcher

import (
	"database/sql"
	"path/filepath"
	"testing"

	"identity-agent-core/store"

	_ "modernc.org/sqlite"
)

// An identity that opted out is not discussed with peers: the cross-check
// answers as it would for one never seen, revealing neither digest nor time.
func TestKelCheckHonoursOptOut(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.ApplyIdentityMigrations(db); err != nil {
		t.Fatal(err)
	}
	applyWatcherTables(t, db)
	st := NewSQLiteStore(db)
	svc := NewService(st)
	if err := svc.RecordFirstSeen("EAID", 1, "Edigest", SourceOOBI, "http://x"); err != nil {
		t.Fatal(err)
	}
	resp, err := svc.KelCheck(KelCheckRequest{AID: "EAID", Seq: 1, Digest: "Edigest"})
	if err != nil || !resp.Match || resp.OurDigest == nil {
		t.Fatalf("before opting out: %+v, %v", resp, err)
	}
	if err := st.SetOptOut("EAID", true); err != nil {
		t.Fatal(err)
	}
	resp, err = svc.KelCheck(KelCheckRequest{AID: "EAID", Seq: 1, Digest: "Edigest"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Match || resp.OurDigest != nil || resp.OurFirstSeen != nil {
		t.Fatalf("an opted-out identity's record was revealed: %+v", resp)
	}
}
