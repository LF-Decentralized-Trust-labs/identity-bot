package recovery

import (
	"errors"
	"testing"

	"identity-agent-core/store"
)

// A restore that stops part-way must leave events with no identity row, never
// an identity row whose log stops early: an owner check reads the log, and a
// log cut before a rotation reads as a stage the identity is not at.

type recordingStore struct {
	store.Store
	order     []string
	failEvent int // fail the Nth SaveEvent (1-based), 0 for never
	events    int
}

func (r *recordingStore) SaveEvent(ev store.EventRecord) error {
	r.events++
	r.order = append(r.order, "event")
	if r.failEvent != 0 && r.events == r.failEvent {
		return errors.New("disk full")
	}
	return r.Store.SaveEvent(ev)
}

func (r *recordingStore) SaveIdentity(id store.IdentityState) error {
	r.order = append(r.order, "identity")
	return r.Store.SaveIdentity(id)
}

func aPayloadOfAnIdentityWithEvents(t *testing.T) *RestoredPayload {
	t.Helper()
	oldDir, oldStore := machineWithAnIdentity(t, "EMyRealIdentity")
	for i := 0; i < 3; i++ {
		if err := oldStore.SaveEvent(store.EventRecord{AID: "EMyRealIdentity", SequenceNumber: i, EventType: "rot", EventJSON: "{}", Timestamp: "2026-01-01T00:00:00Z"}); err != nil {
			t.Fatal(err)
		}
	}
	archive := archiveOf(t, oldDir, oldStore)
	oldStore.Close()
	payload, err := RestoreFromArchive(archive, OpenRequest{Mnemonic: testPhrase})
	if err != nil {
		t.Fatal(err)
	}
	if payload.Identity == nil || len(payload.KelEvents) != 3 {
		t.Fatalf("the archive does not carry the identity and its events: %+v", payload)
	}
	return payload
}

func TestARestoreWritesTheEventsBeforeTheIdentityRow(t *testing.T) {
	payload := aPayloadOfAnIdentityWithEvents(t)
	newDir := t.TempDir()
	inner, err := store.NewSQLiteStore(newDir)
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	rec := &recordingStore{Store: inner}
	if err := NewService(newDir, rec, nil).applyPayload(payload); err != nil {
		t.Fatal(err)
	}
	last := -1
	for i, what := range rec.order {
		if what == "event" {
			last = i
		}
	}
	for i, what := range rec.order {
		if what == "identity" && i < last {
			t.Fatalf("the identity row was written before the last event: %v", rec.order)
		}
	}
	if last < 0 {
		t.Fatalf("no events were written: %v", rec.order)
	}
}

func TestARestoreThatStopsOnAnEventLeavesNoIdentityRow(t *testing.T) {
	payload := aPayloadOfAnIdentityWithEvents(t)
	newDir := t.TempDir()
	inner, err := store.NewSQLiteStore(newDir)
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	rec := &recordingStore{Store: inner, failEvent: 2}
	if err := NewService(newDir, rec, nil).applyPayload(payload); err == nil {
		t.Fatal("the restore reported success though an event could not be written")
	}
	if id, _ := inner.GetIdentity(); id != nil {
		t.Fatalf("an identity row was left behind with only some of its events: %+v", id)
	}
}
