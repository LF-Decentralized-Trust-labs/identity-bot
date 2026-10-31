package store

import "testing"

// An event is found in the log whose event it is, by its own identifier, not
// in a log that merely mentions that identifier (as a later event's prior
// digest does).
func TestAnEventIsFoundInTheLogItBelongsTo(t *testing.T) {
	sq, err := NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fs, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	type eventStore interface {
		SaveEvent(EventRecord) error
		AIDsOfEvent(string) ([]string, error)
	}
	for name, s := range map[string]eventStore{"sqlite": sq, "file": fs} {
		for _, e := range []EventRecord{
			{AID: "EAlice", SequenceNumber: 0, EventType: "icp", EventJSON: `{"d":"EAliceIcp","i":"EAlice"}`},
			{AID: "EAlice", SequenceNumber: 1, EventType: "rot", EventJSON: `{"d":"EAliceRot","i":"EAlice","p":"EAliceIcp"}`},
			{AID: "EBob", SequenceNumber: 0, EventType: "icp", EventJSON: `{"d":"EBobIcp","i":"EBob","a":["EAliceRot"]}`},
		} {
			if err := s.SaveEvent(e); err != nil {
				t.Fatal(err)
			}
		}
		for said, want := range map[string]string{"EAliceIcp": "EAlice", "EAliceRot": "EAlice", "EBobIcp": "EBob"} {
			got, err := s.AIDsOfEvent(said)
			if err != nil || len(got) != 1 || got[0] != want {
				t.Errorf("%s: %s found in %v (%v), want only %s", name, said, got, err, want)
			}
		}
		if got, _ := s.AIDsOfEvent("ENobody"); len(got) != 0 {
			t.Errorf("%s: an event in no log was found in %v", name, got)
		}
		if got, _ := s.AIDsOfEvent(""); len(got) != 0 {
			t.Errorf("%s: an empty identifier was found in %v", name, got)
		}
	}
}
