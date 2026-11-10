package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/store"
)

// A receipt signed over the event is checked against the event before it is
// kept, on either route that stores one. POST /api/store/receipt used to keep
// one on its shape alone, because it never looked the event up.
func TestAReceiptOverTheEventIsKeptOnlyAgainstTheEvent(t *testing.T) {
	w := witnessedIdentity(t)
	id, err := w.s.DataStore.GetIdentity()
	if err != nil || id == nil {
		t.Fatal("no identity", err)
	}
	evs, err := w.s.DataStore.GetEvents(id.AID)
	if err != nil || len(evs) == 0 {
		t.Fatal("no event", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(evs[0].RawBytesB64)
	good, err := drivers.SignEventReceipt(raw, w.keys[0].Seed(), 0)
	if err != nil {
		t.Fatal(err)
	}
	wrongIndex, _ := drivers.SignEventReceipt(raw, w.keys[0].Seed(), 1)
	otherEvent, _ := drivers.SignEventReceipt(append([]byte(nil), raw[:len(raw)-2]...), w.keys[0].Seed(), 0)

	post := func(witness, sig, said string) int {
		b, _ := json.Marshal(map[string]string{"event_said": said, "witness_aid": witness, "cesr_signature": sig})
		rec := httptest.NewRecorder()
		w.s.handleStoreReceipt(rec, local("POST", "/api/store/receipt", string(b)))
		return rec.Code
	}
	held := func() int { h, _ := w.s.DataStore.GetWitnessReceipts(w.said); return len(h) }

	// Right key, a signature over something else: shaped like a receipt, not one.
	if code := post(w.witnesses[0], otherEvent, w.said); code != 422 || held() != 0 {
		t.Fatalf("a signature over other bytes: %d, kept %d", code, held())
	}
	// Right signature, but at a place in the witness list that is another witness's.
	if code := post(w.witnesses[0], wrongIndex, w.said); code != 422 || held() != 0 {
		t.Fatalf("a wrongly indexed receipt: %d, kept %d", code, held())
	}
	// An event no key log kept here holds cannot be checked, so is refused.
	if code := post(w.witnesses[0], good, "ENoSuchEvent0123456789ABCDEFGHIJKLMNOPQRSTU"); code != 404 || held() != 0 {
		t.Fatalf("a receipt for an event nobody here keeps: %d", code)
	}
	if code := post(w.witnesses[0], good, w.said); code != 201 || held() != 1 {
		t.Fatalf("the genuine receipt: %d, kept %d", code, held())
	}
	// The store itself refuses one offered without its event, whichever route.
	if err := w.s.DataStore.SaveWitnessReceipt(store.WitnessReceiptRecord{
		EventSAID: w.said, WitnessAID: w.witnesses[1], CesrSignature: good,
	}); err == nil {
		t.Fatal("the store kept a receipt over the event with no event")
	}
}
