package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"identity-agent-core/store"
)

// An event whose content does not match the identifier it carries is refused
// at the store route, and a receipt for that identifier is not counted for it.
func TestAnEventWithTheWrongIdentifierIsNotStoredOrCounted(t *testing.T) {
	w := witnessedIdentity(t)
	ident, err := w.s.DataStore.GetIdentity()
	if err != nil || ident == nil {
		t.Fatalf("no identity: %v", err)
	}
	genuine, _ := base64.StdEncoding.DecodeString(mustEvents(t, w, ident.AID)[0].RawBytesB64)

	// A witness altered in the content, d left as the genuine event's.
	forged := bytes.Replace(append([]byte(nil), genuine...), []byte(w.witnesses[1]), []byte(w.witnesses[0]), 1)
	if bytes.Equal(forged, genuine) {
		t.Fatal("the test did not alter the event")
	}
	rec := store.EventRecord{
		AID: "EForged", SequenceNumber: 0, EventType: "ixn", EventJSON: string(forged),
		RawBytesB64: base64.StdEncoding.EncodeToString(forged),
	}
	b, _ := json.Marshal(rec)
	noBytes, _ := json.Marshal(store.EventRecord{AID: ident.AID, SequenceNumber: 1, EventType: "ixn"})
	for what, body := range map[string][]byte{"a wrong d": b, "no bytes": noBytes} {
		out := httptest.NewRecorder()
		w.s.handleStoreEvent(out, local("POST", "/api/store/event", string(body)))
		if out.Code < 400 || out.Code >= 500 {
			t.Fatalf("an event with %s was answered %d: %s", what, out.Code, out.Body.String())
		}
	}
	if got, _ := w.s.DataStore.GetEvents("EForged"); len(got) != 0 {
		t.Fatalf("a refused event was stored: %d rows", len(got))
	}

	// Past the route too: a row with a wrong d claims nothing, so the honest
	// receipts for that d count for the genuine event alone.
	rec.EventType = "icp"
	if err := w.s.DataStore.SaveEvent(rec); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		_ = w.s.DataStore.SaveWitnessReceipt(store.WitnessReceiptRecord{
			EventSAID: w.said, WitnessAID: w.witnesses[i], CesrSignature: w.sign(i)})
	}
	if in, ok := w.s.logOfEvent(w.said); !ok || in.AID != ident.AID {
		t.Fatalf("the genuine event was not placed in its own log: %v %v", in.AID, ok)
	}
}

func mustEvents(t *testing.T, w receiptWorld, aid string) []store.EventRecord {
	t.Helper()
	evs, err := w.s.DataStore.GetEvents(aid)
	if err != nil || len(evs) != 1 {
		t.Fatalf("events of %s: %v (%d)", aid, err, len(evs))
	}
	return evs
}
