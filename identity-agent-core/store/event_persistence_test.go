package store

import (
	"path/filepath"
	"testing"
)

func eventStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "identity.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// Both of these columns existed and neither was written, so a signature handed
// to this store was accepted and dropped. That is why identities kept here had
// unsigned inceptions and could convince nobody: a key history containing an
// unsigned event is refused.
func TestAnEventKeepsItsSignatureAndCanonicalBytes(t *testing.T) {
	s := eventStore(t)
	rec := EventRecord{
		AID: "EIdentity", SequenceNumber: 0, EventType: "icp",
		EventJSON: `{"t":"icp"}`, PublicKey: "Dkey", Timestamp: "now",
		CesrSignature: "0Bsignature", RawBytesB64: "cmF3",
	}
	if err := s.SaveEvent(rec); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetEvents("EIdentity")
	if err != nil || len(got) != 1 {
		t.Fatalf("events: %v %d", err, len(got))
	}
	if got[0].CesrSignature != "0Bsignature" {
		t.Errorf("the signature was not kept: %q", got[0].CesrSignature)
	}
	if got[0].RawBytesB64 != "cmF3" {
		t.Errorf("the canonical bytes were not kept: %q", got[0].RawBytesB64)
	}
}

// A signature necessarily arrives after the event it covers — there are no
// bytes to sign until the event exists — so attaching one must be possible.
func TestASignatureCanBeAttachedAfterTheEvent(t *testing.T) {
	s := eventStore(t)
	rec := EventRecord{
		AID: "EIdentity", SequenceNumber: 0, EventType: "icp",
		EventJSON: `{"t":"icp"}`, PublicKey: "Dkey", Timestamp: "now",
		RawBytesB64: "cmF3",
	}
	if err := s.SaveEvent(rec); err != nil {
		t.Fatal(err)
	}
	rec.CesrSignature = "0Blater"
	if err := s.SaveEvent(rec); err != nil {
		t.Fatalf("attaching a signature afterwards failed: %v", err)
	}
	got, _ := s.GetEvents("EIdentity")
	if len(got) != 1 {
		t.Fatalf("re-saving an event produced %d rows; a history with the same event "+
			"twice fails its own chain check", len(got))
	}
	if got[0].CesrSignature != "0Blater" {
		t.Errorf("the attached signature was not kept: %q", got[0].CesrSignature)
	}
}

// A later write that simply does not carry them must not erase what an earlier
// one established.
func TestALaterWriteDoesNotEraseASignature(t *testing.T) {
	s := eventStore(t)
	rec := EventRecord{
		AID: "EIdentity", SequenceNumber: 0, EventType: "icp",
		EventJSON: `{"t":"icp"}`, PublicKey: "Dkey", Timestamp: "now",
		CesrSignature: "0Bkeep", RawBytesB64: "cmF3",
	}
	if err := s.SaveEvent(rec); err != nil {
		t.Fatal(err)
	}
	bare := rec
	bare.CesrSignature = ""
	bare.RawBytesB64 = ""
	if err := s.SaveEvent(bare); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetEvents("EIdentity")
	if got[0].CesrSignature != "0Bkeep" {
		t.Errorf("a write carrying no signature erased the one on file: %q", got[0].CesrSignature)
	}
	if got[0].RawBytesB64 != "cmF3" {
		t.Errorf("a write carrying no bytes erased the ones on file: %q", got[0].RawBytesB64)
	}
}
