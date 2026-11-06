package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/drivers/signedlog"
)

// A backup is restored into a database that already holds the verified log for
// a contact. The held log moves forward only, whether it arrives by
// SaveContactKEL or by a restore.
//
// Fails when mergeContactKELs is replaced by the plain INSERT OR REPLACE copy:
// the fork (and the old backup) become the held log and the retired key current.
func TestARestoredBackupDoesNotWindBackOrForkAHeldContactLog(t *testing.T) {
	keys := signedlog.NewKeys(t, 3)
	atK1 := signedlog.Incept(t, keys)
	atK2 := atK1.Fork().Rotate()
	atK3 := atK2.Fork().Rotate()
	fork := atK2.Fork().Interact("mine").Interact("also mine")

	restoreInto := func(t *testing.T, held, backup *signedlog.Log) (*SQLiteStore, ImportReport) {
		_, from := openStore(t)
		if err := from.SaveContactKEL(record(backup, true)); err != nil {
			t.Fatal(err)
		}
		snap := snapshotOf(t, from)
		_, into := openStore(t)
		if held != nil {
			if err := into.SaveContactKEL(record(held, true)); err != nil {
				t.Fatal(err)
			}
		}
		report, err := into.ImportSnapshotReport(snap)
		if err != nil {
			t.Fatal(err)
		}
		return into, report
	}

	t.Run("a fork signed by a retired key is kept out", func(t *testing.T) {
		into, report := restoreInto(t, atK3, fork)
		got, _ := into.GetContactKEL(atK3.AID)
		if got == nil || got.CurrentPublicKey != keys.Pub(2) || len(got.KEL) != atK3.Len() {
			t.Fatalf("the restore replaced the held log with the fork: %+v", got)
		}
		if report.ContactLogsKept != 1 {
			t.Fatalf("kept = %d, want 1", report.ContactLogsKept)
		}
	})
	t.Run("an ordinary older backup does not wind the contact back", func(t *testing.T) {
		into, report := restoreInto(t, atK3, atK2)
		got, _ := into.GetContactKEL(atK3.AID)
		if got == nil || got.CurrentPublicKey != keys.Pub(2) {
			t.Fatalf("the restore wound the contact back: %+v", got)
		}
		if report.ContactLogsKept != 1 {
			t.Fatalf("kept = %d, want 1", report.ContactLogsKept)
		}
	})
	t.Run("a backup that carries on from the held log is taken", func(t *testing.T) {
		into, report := restoreInto(t, atK2, atK3)
		got, _ := into.GetContactKEL(atK3.AID)
		if got == nil || got.CurrentPublicKey != keys.Pub(2) || len(got.KEL) != atK3.Len() {
			t.Fatalf("the longer log from the backup was not taken: %+v", got)
		}
		if report.ContactLogsKept != 0 {
			t.Fatalf("kept = %d, want 0", report.ContactLogsKept)
		}
	})
	t.Run("a log nothing is held for is taken", func(t *testing.T) {
		into, report := restoreInto(t, nil, atK3)
		got, _ := into.GetContactKEL(atK3.AID)
		if got == nil || !got.KelVerified || len(got.KEL) != atK3.Len() || report.ContactLogsKept != 0 {
			t.Fatalf("got %+v, report %+v", got, report)
		}
	})
}

// A held verified log that cannot be read is not replaced by a restore either.
func TestARestoreDoesNotReplaceAHeldLogItCannotRead(t *testing.T) {
	keys := signedlog.NewKeys(t, 2)
	l := signedlog.Incept(t, keys).Rotate()
	_, from := openStore(t)
	if err := from.SaveContactKEL(record(l, true)); err != nil {
		t.Fatal(err)
	}
	snap := snapshotOf(t, from)
	_, into := openStore(t)
	if err := into.SaveContactKEL(record(l, true)); err != nil {
		t.Fatal(err)
	}
	if _, err := into.db.Exec(`UPDATE contact_kels SET kel_json = 'not json'`); err != nil {
		t.Fatal(err)
	}
	if _, err := into.ImportSnapshotReport(snap); err == nil {
		t.Fatal("a held verified log that cannot be read was replaced by a restore")
	}
}

// An unreadable contact_kels.json is not an empty one. Fails when the load
// error is swallowed again in FileStore.SaveContactKEL: the save goes through
// and every other log in the file is gone.
func TestAnUnreadableContactLogFileRefusesTheSaveAndIsLeftAlone(t *testing.T) {
	keys := signedlog.NewKeys(t, 2)
	l := signedlog.Incept(t, keys)
	dir := t.TempDir()
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.SaveContactKEL(record(l, true)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "contact_kels.json")
	garbled := []byte(`{"truncated": `)
	if err := os.WriteFile(path, garbled, 0600); err != nil {
		t.Fatal(err)
	}
	other := signedlog.Incept(t, signedlog.NewKeys(t, 1))
	err = fs.SaveContactKEL(record(other, true))
	if err == nil || !strings.Contains(err.Error(), "contact_kels.json") {
		t.Fatalf("the save was not refused naming the file: %v", err)
	}
	if errors.Is(err, ErrLogDoesNotExtend) {
		t.Fatalf("wrong error: %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(garbled) {
		t.Fatalf("the unreadable file was overwritten: %q", after)
	}
}

// The current key of a stored verified log is the one its events establish, not
// whatever the row says. A backup holding the exact events a machine already has
// but naming the retired K2 as current must not make K2 current again.
//
// Fails when mergeContactKELs copies current_public_key from the backup again.
func TestARestoredRowIsTakenOnlyWithTheKeyItsEventsEstablish(t *testing.T) {
	keys := signedlog.NewKeys(t, 3)
	atK2 := signedlog.Incept(t, keys).Rotate()
	atK3 := atK2.Fork().Rotate()

	backupNaming := func(t *testing.T, key string) string {
		_, from := openStore(t)
		if err := from.SaveContactKEL(record(atK3, true)); err != nil {
			t.Fatal(err)
		}
		if _, err := from.db.Exec(`UPDATE contact_kels SET current_public_key = ?`, key); err != nil {
			t.Fatal(err)
		}
		return snapshotOf(t, from)
	}

	t.Run("the exact held events with the retired key stated are refused", func(t *testing.T) {
		snap := backupNaming(t, keys.Pub(1))
		_, into := openStore(t)
		if err := into.SaveContactKEL(record(atK3, true)); err != nil {
			t.Fatal(err)
		}
		report, err := into.ImportSnapshotReport(snap)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := into.GetContactKEL(atK3.AID)
		if got == nil || got.CurrentPublicKey != keys.Pub(2) {
			t.Fatalf("the retired key became current: %+v", got)
		}
		if report.ContactLogsKept != 1 {
			t.Fatalf("kept = %d, want 1", report.ContactLogsKept)
		}
	})
	t.Run("a refused row is not put back when nothing is held either", func(t *testing.T) {
		snap := backupNaming(t, keys.Pub(1))
		_, into := openStore(t)
		if _, err := into.ImportSnapshotReport(snap); err != nil {
			t.Fatal(err)
		}
		if got, _ := into.GetContactKEL(atK3.AID); got != nil && got.CurrentPublicKey == keys.Pub(1) {
			t.Fatalf("the retired key was restored: %+v", got)
		}
	})
	t.Run("a row stating no key gets the one its events establish", func(t *testing.T) {
		snap := backupNaming(t, "")
		_, into := openStore(t)
		if _, err := into.ImportSnapshotReport(snap); err != nil {
			t.Fatal(err)
		}
		got, _ := into.GetContactKEL(atK3.AID)
		if got == nil || got.CurrentPublicKey != keys.Pub(2) {
			t.Fatalf("got %+v", got)
		}
	})
}

// SaveContactKEL, in either store, does not store a key its own events do not
// establish. Fails when settleCurrentKey is dropped from the save.
func TestASavedLogCannotStateAKeyItsEventsDoNotEstablish(t *testing.T) {
	keys := signedlog.NewKeys(t, 3)
	atK3 := signedlog.Incept(t, keys).Rotate().Rotate()
	fs, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, sq := openStore(t)
	for name, st := range map[string]interface {
		SaveContactKEL(ContactKELRecord) error
		GetContactKEL(string) (*ContactKELRecord, error)
	}{"file": fs, "sqlite": sq} {
		t.Run(name, func(t *testing.T) {
			bad := record(atK3, true)
			bad.CurrentPublicKey = keys.Pub(1)
			if err := st.SaveContactKEL(bad); !errors.Is(err, ErrKeyNotEstablished) {
				t.Fatalf("a retired key was saved as current: %v", err)
			}
			if got, _ := st.GetContactKEL(atK3.AID); got != nil {
				t.Fatalf("something was stored: %+v", got)
			}
			ok := record(atK3, true)
			ok.CurrentPublicKey = ""
			if err := st.SaveContactKEL(ok); err != nil {
				t.Fatal(err)
			}
			if got, _ := st.GetContactKEL(atK3.AID); got == nil || got.CurrentPublicKey != keys.Pub(2) {
				t.Fatalf("got %+v", got)
			}
		})
	}
}
