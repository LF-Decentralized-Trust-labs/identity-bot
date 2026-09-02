package store

import "testing"

// A later write never blanks what an event is checked against.
//
// The signature on an event is verified against the key that event names, and
// the route that attaches one refuses an event naming no key. So a write that
// carried an empty key would not merely lose information — it would make that
// event permanently unsignable, and an unsigned founding is one no counterparty
// accepts. One request could do it.
//
// The same rule already covered the signature and the canonical bytes. The key
// sat between them without it.
func TestAnEventKeepsTheKeyAndSignatureThatProveIt(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}

	const aid = "EIDENTITY"
	if err := s.SaveEvent(EventRecord{
		AID: aid, SequenceNumber: 0, EventType: "icp",
		PublicKey:     "DTHEFOUNDINGKEY",
		RawBytesB64:   "dGhlIGJ5dGVz",
		CesrSignature: "0BTHESIGNATURE",
	}); err != nil {
		t.Fatal(err)
	}

	// A later write about the same event that simply does not carry them.
	if err := s.SaveEvent(EventRecord{
		AID: aid, SequenceNumber: 0, EventType: "icp",
		EventJSON: `{"updated":true}`,
	}); err != nil {
		t.Fatal(err)
	}

	events, err := s.GetEvents(aid)
	if err != nil || len(events) != 1 {
		t.Fatalf("expected one event, got %d (%v)", len(events), err)
	}
	got := events[0]
	if got.PublicKey != "DTHEFOUNDINGKEY" {
		t.Errorf("the key this event is checked against was blanked (%q), which "+
			"leaves it unverifiable and unsignable", got.PublicKey)
	}
	if got.CesrSignature != "0BTHESIGNATURE" {
		t.Errorf("the signature was blanked (%q)", got.CesrSignature)
	}
	if got.RawBytesB64 != "dGhlIGJ5dGVz" {
		t.Errorf("the bytes a signature covers were blanked (%q)", got.RawBytesB64)
	}
	// And what the later write DID carry is kept.
	if got.EventJSON != `{"updated":true}` {
		t.Errorf("the later write was ignored entirely: %q", got.EventJSON)
	}
}
