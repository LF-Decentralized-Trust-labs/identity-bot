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

// A rotation that cuts every witness leaves a list that was read and has
// nobody in it. It answers an empty list, not nil, and the rotation's own
// threshold, so no caller takes it for a list nobody read.
func TestARotationThatCutsEveryWitnessLeavesAnEmptyListNotNil(t *testing.T) {
	ds, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ds.Close()
	keptEvent(t, ds, "EAid", 0, `{"t":"icp","d":"E0","i":"EAid","s":"0","b":["BW1","BW2"],"bt":"2"}`)
	core := &CoreServer{DataStore: ds}
	rot := map[string]interface{}{"t": "rot", "d": "E1", "i": "EAid", "s": "1",
		"br": []interface{}{"BW1", "BW2"}, "ba": []interface{}{}, "bt": "0"}
	keys, toad, err := core.designationAfter("EAid", rot)
	if err != nil {
		t.Fatal(err)
	}
	if keys == nil || len(keys) != 0 || toad != 0 {
		t.Fatalf("a cut-all rotation answered %#v, toad %d", keys, toad)
	}
	// And the same once the rotation is in the log.
	keptEvent(t, ds, "EAid", 1, `{"t":"rot","d":"E1","i":"EAid","s":"1","br":["BW1","BW2"],"ba":[],"bt":"0"}`)
	if keys, toad, err = core.designationAfter("EAid", nil); err != nil || keys == nil || len(keys) != 0 || toad != 0 {
		t.Fatalf("a logged cut-all rotation answered %#v, %d, %v", keys, toad, err)
	}
}

// An event that cannot be read could be the rotation that cut a witness, so
// the log is unreadable and the answer is an error, not the list without it.
func TestADamagedEventMakesTheLogUnreadableNotShorter(t *testing.T) {
	ds, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ds.Close()
	keptEvent(t, ds, "EAid", 0, `{"t":"icp","d":"E0","i":"EAid","s":"0","b":["BW1"],"bt":"1"}`)
	keptEvent(t, ds, "EAid", 1, `{"t":"rot", this is damaged`)
	core := &CoreServer{DataStore: ds}
	if keys, _, err := core.designationAfter("EAid", nil); err == nil {
		t.Fatalf("a log with a damaged rotation answered %v and no error", keys)
	}
	if _, _, err := (&CoreServer{}).designationAfter("EAid", nil); err == nil {
		t.Fatal("no log to read answered without an error")
	}
}
