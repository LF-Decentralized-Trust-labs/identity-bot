package store

import (
	"encoding/json"
	"errors"
	"testing"

	"identity-agent-core/drivers/signedlog"
)

// A backup's kel_verified flag is a claim by whoever made the file. A backup
// holding the held K3 log plus a rotation to an attacker's key that the log's
// own keys never signed must not take over, though it says "verified".
//
// Fails when mergeContactKELs stops calling reverify: the attacker's key
// becomes current.
func TestARestoredRowMarkedVerifiedIsValidatedAgain(t *testing.T) {
	keys := signedlog.NewKeys(t, 3)
	attacker := signedlog.NewKeys(t, 2)
	atK3 := signedlog.Incept(t, keys).Rotate().Rotate()
	forged := atK3.Fork().RotateTo(attacker)
	if forged.Verdict().KelVerified {
		t.Fatal("test setup: the forged log verifies")
	}

	forgedBackup := func(t *testing.T) string {
		_, from := openStore(t)
		if err := from.SaveContactKEL(record(atK3, true)); err != nil {
			t.Fatal(err)
		}
		rec := record(forged, true)
		rec.CurrentPublicKey = attacker.Pub(0)
		kel, _ := json.Marshal(rec.KEL)
		if _, err := from.db.Exec(`UPDATE contact_kels SET kel_json = ?, kel_verified = 1, current_public_key = ?`,
			kel, attacker.Pub(0)); err != nil {
			t.Fatal(err)
		}
		return snapshotOf(t, from)
	}

	t.Run("the held log is kept", func(t *testing.T) {
		snap := forgedBackup(t)
		_, into := openStore(t)
		if err := into.SaveContactKEL(record(atK3, true)); err != nil {
			t.Fatal(err)
		}
		report, err := into.ImportSnapshotReport(snap)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := into.GetContactKEL(atK3.AID)
		if got == nil || got.CurrentPublicKey != keys.Pub(2) || len(got.KEL) != atK3.Len() {
			t.Fatalf("the attacker's key became current: %+v", got)
		}
		if report.ContactLogsKept != 1 {
			t.Fatalf("kept = %d, want 1", report.ContactLogsKept)
		}
	})
	t.Run("with nothing held it is not restored as verified", func(t *testing.T) {
		snap := forgedBackup(t)
		_, into := openStore(t)
		if _, err := into.ImportSnapshotReport(snap); err != nil {
			t.Fatal(err)
		}
		if got, _ := into.GetContactKEL(atK3.AID); got != nil && got.KelVerified {
			t.Fatalf("an unsigned rotation was restored as verified: %+v", got)
		}
	})
}

// A row carries its own identifier, and its events must belong to it. Fails
// when the identifier check is dropped from KeyEstablishedBy (the save) or the
// restore stops validating again (the restore).
func TestALogOfAnotherIdentifierIsNotStoredUnderThisOne(t *testing.T) {
	a := signedlog.Incept(t, signedlog.NewKeys(t, 2)).Rotate()
	b := signedlog.Incept(t, signedlog.NewKeys(t, 2))

	t.Run("a save is refused", func(t *testing.T) {
		bothStores(t, func(t *testing.T, st contactLogs) {
			rec := record(a, true)
			rec.AID = b.AID
			rec.CurrentPublicKey = ""
			if err := st.SaveContactKEL(rec); !errors.Is(err, ErrKeyNotEstablished) {
				t.Fatalf("another identifier's log was saved: %v", err)
			}
			if got, _ := st.GetContactKEL(b.AID); got != nil {
				t.Fatalf("something was stored: %+v", got)
			}
		})
	})
	t.Run("a restore does not take it as verified", func(t *testing.T) {
		_, from := openStore(t)
		if err := from.SaveContactKEL(record(b, true)); err != nil {
			t.Fatal(err)
		}
		kel, _ := json.Marshal(a.Records())
		if _, err := from.db.Exec(`UPDATE contact_kels SET kel_json = ?, kel_verified = 1, current_public_key = ?`,
			kel, a.Key()); err != nil {
			t.Fatal(err)
		}
		snap := snapshotOf(t, from)
		_, into := openStore(t)
		if _, err := into.ImportSnapshotReport(snap); err != nil {
			t.Fatal(err)
		}
		if got, _ := into.GetContactKEL(b.AID); got != nil && got.KelVerified {
			t.Fatalf("another identifier's log was restored as this one's: %+v", got)
		}
	})
}
