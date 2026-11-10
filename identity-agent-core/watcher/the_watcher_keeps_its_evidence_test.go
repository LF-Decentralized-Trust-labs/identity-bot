package watcher

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func evidenceService(t *testing.T) *Service {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	applyWatcherTables(t, db)
	return NewService(NewSQLiteStore(db))
}

// An L2 that cannot answer is recorded as asked-and-unavailable, not left out.
func TestAnUnavailableL2IsInTheEvidence(t *testing.T) {
	ws := evidenceService(t)
	// Nothing listens here, so the query fails.
	if err := ws.Store.SetConfig("default_l2_url", "http://127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	kel := []map[string]interface{}{{"v": "KERI10JSON000256_", "t": "icp", "i": "EBob", "s": "0"}}
	res, err := ws.VerifyKel(context.Background(), VerifyKelInput{AID: "EBob", KEL: kel, SourceType: SourceOOBI})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range res.SourcesQueried {
		if o.Type == "L2_standing" {
			if o.Outcome != "unavailable" {
				t.Fatalf("L2 outcome = %q, want unavailable", o.Outcome)
			}
			return
		}
	}
	t.Fatalf("L2 was queried and failed but is absent from the evidence: %+v", res.SourcesQueried)
}

// Observations at every position survive verification, so a later fork at an
// intermediate position is duplicity and not a first sighting.
func TestAForkAtAnEarlierPositionIsStillCaught(t *testing.T) {
	ws := evidenceService(t)
	ws.Store.SetConfig("default_l2_url", "http://127.0.0.1:1")
	for seq := 0; seq < 5; seq++ {
		if err := ws.RecordFirstSeen("EBob", seq, fmt.Sprintf("Ed%d", seq), SourceOOBI, ""); err != nil {
			t.Fatal(err)
		}
	}
	kel := []map[string]interface{}{{"v": "KERI10JSON000256_", "t": "icp", "i": "EBob", "s": "4"}}
	if _, err := ws.VerifyKel(context.Background(), VerifyKelInput{AID: "EBob", KEL: kel, SourceType: SourceOOBI}); err != nil {
		t.Fatal(err)
	}
	rows, _ := ws.Store.ListFirstSeen("EBob")
	if len(rows) != 5 {
		t.Fatalf("%d observations kept, want 5", len(rows))
	}
	dup, _, err := ws.DetectDuplicity("EBob", 2, "Eforked")
	if err != nil || !dup {
		t.Fatalf("fork at seq 2: dup=%v err=%v", dup, err)
	}
}

// The first digest stands; a different one is a conflict that is recorded.
func TestTheFirstDigestIsNotOverwritten(t *testing.T) {
	ws := evidenceService(t)
	now := time.Now().UTC()
	rec := FirstSeenRecord{AID: "EAl", SequenceNum: 1, KelDigest: "Efirst", FirstSeenAt: now, LastConfirmedAt: now, SeenCount: 1, SourceType: SourceOOBI}
	if err := ws.Store.RecordFirstSeen(rec); err != nil {
		t.Fatal(err)
	}
	rec.KelDigest = "Elater"
	if err := ws.Store.RecordFirstSeen(rec); !errors.Is(err, ErrFirstSeenConflict) {
		t.Fatalf("store: err = %v, want ErrFirstSeenConflict", err)
	}
	if err := ws.RecordFirstSeen("EAl", 1, "Elater", SourceOOBI, "http://x"); !errors.Is(err, ErrFirstSeenConflict) {
		t.Fatalf("service: err = %v, want ErrFirstSeenConflict", err)
	}
	got, _ := ws.Store.GetFirstSeen("EAl", 1)
	if got.KelDigest != "Efirst" {
		t.Fatalf("first digest replaced: %s", got.KelDigest)
	}
	alerts, _ := ws.Store.ListDuplicityAlerts("EAl")
	if len(alerts) == 0 || alerts[0].OurDigest != "Efirst" || alerts[0].TheirDigest != "Elater" {
		t.Fatalf("conflict not recorded: %+v", alerts)
	}
	// The same digest still reinforces.
	if err := ws.RecordFirstSeen("EAl", 1, "Efirst", SourceOOBI, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ = ws.Store.GetFirstSeen("EAl", 1); got.SeenCount != 2 {
		t.Fatalf("seen_count = %d, want 2", got.SeenCount)
	}
}
