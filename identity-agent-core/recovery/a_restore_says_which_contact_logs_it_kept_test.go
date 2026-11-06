package recovery

import (
	"testing"

	"identity-agent-core/drivers/signedlog"
	"identity-agent-core/store"
)

// A whole restore from a backup that holds an older log for a contact, onto a
// machine that holds a later verified one: the later log stays, and the
// restore result (applyPayloadReporting, which Activate puts in
// Session.ContactLogsKept) says one log was kept.
func TestARestoreSaysHowManyContactLogsItKept(t *testing.T) {
	keys := signedlog.NewKeys(t, 3)
	atK2 := signedlog.Incept(t, keys).Rotate()
	atK3 := atK2.Fork().Rotate()
	rec := func(l *signedlog.Log) store.ContactKELRecord {
		return store.ContactKELRecord{AID: l.AID, KEL: l.Records(), KelVerified: true,
			EventsValidated: l.Len(), CurrentPublicKey: l.Key()}
	}

	oldDir, oldStore := machineWithAnIdentity(t, "EKeptLogs")
	if err := oldStore.SaveContactKEL(rec(atK2)); err != nil {
		t.Fatal(err)
	}
	archive := archiveWithTheDefaultTiers(t, oldDir, oldStore)
	oldStore.Close()

	newDir := t.TempDir()
	newStore, err := store.NewSQLiteStore(newDir)
	if err != nil {
		t.Fatal(err)
	}
	defer newStore.Close()
	if err := newStore.SaveContactKEL(rec(atK3)); err != nil {
		t.Fatal(err)
	}

	payload, err := RestoreFromArchive(archive, OpenRequest{Mnemonic: testPhrase})
	if err != nil {
		t.Fatal(err)
	}
	var kept int
	if err := NewService(newDir, newStore, nil).applyPayloadReporting(payload, &kept); err != nil {
		t.Fatalf("the restore failed: %v", err)
	}
	if kept != 1 {
		t.Fatalf("the restore reported %d contact logs kept, want 1", kept)
	}
	if got, _ := newStore.GetContactKEL(atK3.AID); got == nil || len(got.KEL) != atK3.Len() {
		t.Fatalf("the held log was wound back: %+v", got)
	}
}
