package watcher

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"identity-agent-core/store"

	_ "modernc.org/sqlite"
)

func optOutTestService(t *testing.T) (*Service, *SQLiteStore) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.ApplyIdentityMigrations(db); err != nil {
		t.Fatal(err)
	}
	applyWatcherTables(t, db)
	st := NewSQLiteStore(db)
	return NewService(st), st
}

// The duplicity alerts about an identity go through the same opt-out check as
// its first-seen records: once it opts out they read as for one never seen.
func TestAnOptedOutIdentitysDuplicityAlertsAreNotDisclosed(t *testing.T) {
	svc, st := optOutTestService(t)
	if _, err := st.InsertDuplicityAlert(DuplicityAlert{
		AID: "EAID", SequenceNum: 1, OurDigest: "Eours", TheirDigest: "Etheirs", DetectedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if alerts, err := svc.DisclosableAlerts("EAID"); err != nil || len(alerts) != 1 || alerts[0].TheirDigest != "Etheirs" {
		t.Fatalf("before opting out the alert should be readable: %+v, %v", alerts, err)
	}
	if err := st.SetOptOut("EAID", true); err != nil {
		t.Fatal(err)
	}
	if alerts, err := svc.DisclosableAlerts("EAID"); err != nil || alerts != nil {
		t.Fatalf("an opted-out identity's alert was disclosed: %+v, %v", alerts, err)
	}
	if alerts, err := svc.DisclosableAlerts("ENeverSeen"); err != nil || alerts != nil {
		t.Fatalf("an identity never seen should have no alerts: %+v, %v", alerts, err)
	}
}

// countingStore counts every call a read makes on the store.
type countingStore struct {
	Store
	calls int
}

func (c *countingStore) IsOptedOut(aid string) (bool, error) {
	c.calls++
	return c.Store.IsOptedOut(aid)
}
func (c *countingStore) getFirstSeen(aid string, seq int) (*FirstSeenRecord, error) {
	c.calls++
	return c.Store.getFirstSeen(aid, seq)
}
func (c *countingStore) listFirstSeen(aid string) ([]FirstSeenRecord, error) {
	c.calls++
	return c.Store.listFirstSeen(aid)
}
func (c *countingStore) listDuplicityAlerts(aid string) ([]DuplicityAlert, error) {
	c.calls++
	return c.Store.listDuplicityAlerts(aid)
}

// Answering about an opted-out identity makes the same store calls as answering
// about one never seen, so how long the answer takes does not tell them apart.
func TestAnOptedOutIdentityCostsTheSameQueriesAsOneNeverSeen(t *testing.T) {
	svc, st := optOutTestService(t)
	if err := svc.RecordFirstSeen("EOptedOut", 1, "Edigest", SourceOOBI, "http://x"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetOptOut("EOptedOut", true); err != nil {
		t.Fatal(err)
	}
	counted := &countingStore{Store: st}
	svc.Store = counted
	for name, read := range map[string]func(aid string){
		"Disclosable":       func(aid string) { _, _ = svc.Disclosable(aid, 1) },
		"DisclosableAll":    func(aid string) { _, _ = svc.DisclosableAll(aid) },
		"DisclosableAlerts": func(aid string) { _, _ = svc.DisclosableAlerts(aid) },
	} {
		counted.calls = 0
		read("EOptedOut")
		optedOut := counted.calls
		counted.calls = 0
		read("ENeverSeen")
		if optedOut != counted.calls {
			t.Errorf("%s: an opted-out identity costs %d store calls, one never seen %d", name, optedOut, counted.calls)
		}
	}
}
