package watcher

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"identity-agent-core/store"
)

// migratedWatcher is a watcher over a fully migrated identity database whose
// standing watcher cannot be reached, so only this Identity Agent's own memory decides.
func migratedWatcher(t *testing.T) (*Service, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "identity.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.ApplyIdentityMigrations(db); err != nil {
		t.Fatal(err)
	}
	ws := NewService(NewSQLiteStore(db))
	if err := ws.Store.SetConfig("default_l2_url", "http://127.0.0.1:1/public/kel-digest"); err != nil {
		t.Fatal(err)
	}
	return ws, db
}

// keyLog is an identity's log of n events, numbered as KERI numbers them.
func keyLog(aid string, n int) []map[string]interface{} {
	kel := make([]map[string]interface{}, 0, n)
	for i := 0; i < n; i++ {
		t := "ixn"
		if i == 0 {
			t = "icp"
		}
		kel = append(kel, map[string]interface{}{
			"v": "KERI10JSON000160_", "t": t, "i": aid, "s": fmt.Sprintf("%x", i),
			"d": fmt.Sprintf("Eevent-%d", i),
		})
	}
	return kel
}

// An identity whose log grows past its tenth event is the same identity.
//
// Reading the sequence number as decimal put events "a" to "f" at 0, so the
// position stayed at 9 while the digest there changed with every new event —
// and the second time the identity was seen it was refused as duplicitous.
func TestALogOfMoreThanSixteenEventsIsNotDuplicitous(t *testing.T) {
	ws, _ := migratedWatcher(t)
	aid := "EGrowing000000000000000000000000000000000000"
	for n := 1; n <= 24; n++ {
		for pass := 0; pass < 2; pass++ {
			res, err := ws.VerifyKel(context.Background(), VerifyKelInput{
				AID: aid, KEL: keyLog(aid, n), SourceType: SourceOOBI,
			})
			if err != nil {
				t.Fatalf("%d events: %v", n, err)
			}
			if res.Blocked || !res.OK {
				t.Fatalf("%d events, pass %d: refused as %q (%s)", n, pass+1, res.OverallOutcome, res.Reason)
			}
			if res.SequenceNum != n-1 {
				t.Fatalf("%d events placed at position %d, want %d", n, res.SequenceNum, n-1)
			}
		}
	}
}

// An observation recorded before the fix is forgotten by the migration, and
// the identity it made look duplicitous is accepted again.
func TestAnObservationRecordedWithADecimalSequenceIsForgotten(t *testing.T) {
	ws, db := migratedWatcher(t)
	aid := "EStale0000000000000000000000000000000000000"
	twelve := keyLog(aid, 12)

	// What the decimal reading recorded for a twelve-event log: position 9,
	// with a digest over every event in it.
	wrong, err := witnessproto.KelDigestAtSeq(twelve, 11)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := ws.Store.RecordFirstSeen(FirstSeenRecord{
		AID: aid, SequenceNum: 9, KelDigest: wrong, FirstSeenAt: now, LastConfirmedAt: now,
		SeenCount: 1, SourceType: SourceOOBI,
	}); err != nil {
		t.Fatal(err)
	}
	// A sound observation below position 9 survives.
	sound, _ := witnessproto.KelDigestAtSeq(twelve, 3)
	_ = ws.Store.RecordFirstSeen(FirstSeenRecord{
		AID: aid, SequenceNum: 3, KelDigest: sound, FirstSeenAt: now, LastConfirmedAt: now,
		SeenCount: 1, SourceType: SourceOOBI,
	})

	// The identity's first ten events, from a source that has not caught up.
	ten := keyLog(aid, 10)
	before, err := ws.VerifyKel(context.Background(), VerifyKelInput{AID: aid, KEL: ten, SourceType: SourceCredential})
	if err != nil {
		t.Fatal(err)
	}
	if !before.Blocked {
		t.Fatal("the stale observation did not make the identity look duplicitous, so this test proves nothing")
	}

	// Upgrade: the migration runs on a database that has not had it.
	if err := store.ReapplyIdentityMigration(db, 45); err != nil {
		t.Fatal(err)
	}

	after, err := ws.VerifyKel(context.Background(), VerifyKelInput{AID: aid, KEL: ten, SourceType: SourceCredential})
	if err != nil {
		t.Fatal(err)
	}
	if after.Blocked || !after.OK {
		t.Fatalf("still refused after the migration: %s", after.Reason)
	}
	if kept, _ := ws.Store.GetFirstSeen(aid, 3); kept == nil || kept.KelDigest != sound {
		t.Fatalf("the sound observation at position 3 was not kept: %+v", kept)
	}
	alerts, err := ws.Store.ListDuplicityAlerts(aid)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || !alerts[0].Resolved || alerts[0].ResolutionNote == "" {
		t.Fatalf("the alert the stale observation raised is not closed with a reason: %+v", alerts)
	}
}

// A log the watcher cannot place is refused, not waved through unchecked.
func TestAnUnreadableSequenceNumberIsRefused(t *testing.T) {
	ws, _ := migratedWatcher(t)
	aid := "EUnreadable000000000000000000000000000000000"
	kel := keyLog(aid, 3)
	kel[1]["s"] = "zz"
	res, err := ws.VerifyKel(context.Background(), VerifyKelInput{AID: aid, KEL: kel, SourceType: SourceOOBI})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Blocked || res.OK {
		t.Fatalf("a log with an unreadable sequence number was not refused: %+v", res)
	}
}
