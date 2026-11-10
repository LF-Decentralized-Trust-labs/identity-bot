package server

import (
	"encoding/base64"
	"testing"

	"identity-agent-core/store"
)

func keptEvent(t *testing.T, ds *store.SQLiteStore, aid string, sn int, json string) {
	t.Helper()
	if err := ds.SaveEvent(store.EventRecord{AID: aid, SequenceNumber: sn, EventType: "x",
		EventJSON: json, RawBytesB64: base64.StdEncoding.EncodeToString([]byte(json))}); err != nil {
		t.Fatal(err)
	}
}

// A log is read in full. An event that cannot be read could be the rotation
// that cut a witness, so the log is unreadable, not shorter.
func TestADamagedEventMakesTheLogUnreadableNotShorter(t *testing.T) {
	ds, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ds.Close()
	keptEvent(t, ds, "EAid", 0, `{"t":"icp","d":"E0","i":"EAid","s":"0","b":["BW1"],"bt":"1"}`)
	core := &CoreServer{DataStore: ds}
	if log, err := core.keyLogOf("EAid"); err != nil || len(log) != 1 {
		t.Fatalf("a readable log answered %d events and %v", len(log), err)
	}
	keptEvent(t, ds, "EAid", 1, `{"t":"rot", this is damaged`)
	if _, err := core.keyLogOf("EAid"); err != nil {
		// The bytes decode; whether they parse is the rule's to say.
		t.Fatalf("bytes that decode were refused as a log: %v", err)
	}
	if _, err := (&CoreServer{}).keyLogOf("EAid"); err == nil {
		t.Fatal("no store to read answered without an error")
	}
	if err := ds.SaveEvent(store.EventRecord{AID: "EAid", SequenceNumber: 2, EventType: "x", EventJSON: "{}", RawBytesB64: "!!not base64"}); err != nil {
		t.Fatal(err)
	}
	if log, err := core.keyLogOf("EAid"); err == nil {
		t.Fatalf("a log with an event that does not decode answered %d events", len(log))
	}
}

// An identifier the store holds no events for has no log to read: an error, not
// an empty log that would say it designates nobody.
func TestAnIdentifierWithNoEventsInTheStoreIsAnErrorNotAnEmptyLog(t *testing.T) {
	ds, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ds.Close()
	keptEvent(t, ds, "EOther", 0, `{"t":"icp","d":"E0","i":"EOther","s":"0","b":["BW1"],"bt":"1"}`)
	core := &CoreServer{DataStore: ds}
	if log, err := core.keyLogOf("ENobody"); err == nil {
		t.Fatalf("an identifier with no events answered %d events and no error", len(log))
	}
}
