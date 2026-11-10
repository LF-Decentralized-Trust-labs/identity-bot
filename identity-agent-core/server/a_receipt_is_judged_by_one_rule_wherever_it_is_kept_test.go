package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/store"
	"identity-agent-core/witness"
)

func storeReceipt(t *testing.T, s *CoreServer, said, witnessAID, sig string) int {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"event_said": said, "witness_aid": witnessAID, "cesr_signature": sig})
	rec := httptest.NewRecorder()
	s.handleStoreReceipt(rec, local("POST", "/api/store/receipt", string(b)))
	return rec.Code
}

// A receipt kept through POST /api/store/receipt is counted on the event's
// finalization, as one that came back in a witness's answer is.
func TestAStoredReceiptIsCountedOnTheEventsFinalization(t *testing.T) {
	s, _, saids, witnesses, sign := cutByARotation(t)
	if f, _ := s.WitnessService.Store.GetFinalization(saids[0]); f == nil || f.ReceiptCount != 0 {
		t.Fatalf("event 0 starts with a receipt: %+v", f)
	}
	if code := storeReceipt(t, s, saids[0], witnesses[0], sign(0, saids[0])); code != 201 {
		t.Fatalf("the receipt of the designated witness: %d", code)
	}
	f, _ := s.WitnessService.Store.GetFinalization(saids[0])
	if f.ReceiptCount != 1 || f.State != witness.FinalizeFinalized {
		t.Fatalf("a stored receipt was not counted: %+v", f)
	}
}

// POST /api/store/receipt refuses a receipt from a witness the key log does not
// designate at that event, though its signature verifies, and keeps nothing.
func TestAStoredReceiptFromAnUndesignatedWitnessIsRefused(t *testing.T) {
	s, _, saids, witnesses, sign := cutByARotation(t)
	// The second witness is designated only from event 1, and its signature over
	// event 0 verifies all the same.
	if code := storeReceipt(t, s, saids[0], witnesses[1], sign(1, saids[0])); code != 422 {
		t.Fatalf("a receipt from a witness event 0 does not designate: %d, want 422", code)
	}
	if held, _ := s.DataStore.GetWitnessReceipts(saids[0]); len(held) != 0 {
		t.Fatalf("it was kept: %+v", held)
	}
	if f, _ := s.WitnessService.Store.GetFinalization(saids[0]); f != nil && f.ReceiptCount != 0 {
		t.Fatalf("it was counted: %+v", f)
	}
	if code := storeReceipt(t, s, saids[1], witnesses[1], sign(1, saids[1])); code != 201 {
		t.Fatalf("the receipt of a witness event 1 designates: %d", code)
	}
}

// POST /api/receipt/submit refuses a receipt from a witness the key log does not
// designate at that event, as the witness service does, and keeps nothing.
func TestASubmittedReceiptFromAnUndesignatedWitnessIsRefused(t *testing.T) {
	s, _, saids, witnesses, sign := cutByARotation(t)
	// The second witness is designated only from event 1.
	if code := submitReceipt(t, s, saids[0], witnesses[1], sign(1, saids[0])); code != 422 {
		t.Fatalf("a receipt from a witness event 0 does not designate: %d, want 422", code)
	}
	if held, _ := s.DataStore.GetWitnessReceipts(saids[0]); len(held) != 0 {
		t.Fatalf("it was kept: %+v", held)
	}
	if code := submitReceipt(t, s, saids[1], witnesses[1], sign(1, saids[1])); code != 200 {
		t.Fatalf("the receipt of a witness event 1 designates: %d", code)
	}
}

// What the key log designates is read by the one rule for the list in force, so
// a log with an event that does not parse names nobody to ask, rather than the
// list as it stood before the event.
func TestAKeyLogWithAnUnreadableEventNamesNoWitnesses(t *testing.T) {
	w := witnessedIdentity(t)
	id, _ := w.s.DataStore.GetIdentity()
	evs, _ := w.s.DataStore.GetEvents(id.AID)
	icp, _ := base64.StdEncoding.DecodeString(evs[0].RawBytesB64)
	if got := currentWitnessKeys([][]byte{icp}); len(got) != 2 || got[0] != w.witnesses[0] || got[1] != w.witnesses[1] {
		t.Fatalf("the inception's witnesses: %v", got)
	}
	if got := currentWitnessKeys([][]byte{icp, []byte(`{"t":"rot", damaged`)}); got != nil {
		t.Fatalf("a log with an unreadable event named witnesses: %v", got)
	}
}

// An approved record identity is found from a log read whole. An event the key
// log's parser rejects is an error, not an event passed over.
func TestApprovedRecordIdentitiesAreNotFoundFromAPartlyReadLog(t *testing.T) {
	w := witnessedIdentity(t)
	id, _ := w.s.DataStore.GetIdentity()
	damaged := `{"t":"rot", this is damaged`
	if err := w.s.DataStore.SaveEvent(store.EventRecord{AID: id.AID, SequenceNumber: 1, EventType: "rot",
		EventJSON: damaged, RawBytesB64: base64.StdEncoding.EncodeToString([]byte(damaged))}); err != nil {
		t.Fatal(err)
	}
	// The error is about the log, not about something further on.
	if _, err := w.s.approvedRecordIdentities(id.AID); err == nil || !strings.Contains(err.Error(), "key log of "+id.AID) {
		t.Fatalf("a log with an event that does not parse was read as if it did: %v", err)
	}
}
