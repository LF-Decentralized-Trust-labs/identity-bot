package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"identity-agent-core/keriengine"
	"identity-agent-core/store"
)

// A contact stored the normal way, by resolving its OOBI, is one recovery can
// find witnesses for.
//
// Every other recovery test writes the contact's key log into the store by hand,
// which is how a log that has no top-level `b` field, as no stored log has,
// went unnoticed: witnesses must come from the bytes each event was published
// as. This one stores the log through POST /contacts/resolve (the handler a
// person's "add a contact" ends in), with the real key log engine checking it,
// and recovers through what that wrote.
func TestRecoveryFindsTheWitnessesOfAContactStoredByResolvingItsOOBI(t *testing.T) {
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1")

	// The contact, as its own witness-held log has it, naming one witness.
	other := anEndpointWitness(t)
	witnessName := aWitnessName()
	contact := holdAnIdentityNaming(t, other.core.WitnessService.Store, true, []string{witnessName})
	held, err := other.core.WitnessService.Store.GetKelEvents(contact.aid)
	if err != nil || len(held) != 2 {
		t.Fatalf("%d events, %v", len(held), err)
	}
	// What the contact's own OOBI route serves: its events as the store keeps them.
	var events []store.EventRecord
	for _, e := range held {
		events = append(events, store.EventRecord{
			AID: contact.aid, SequenceNumber: e.SequenceNum, EventJSON: e.EventJSON,
			RawBytesB64: e.RawBytesB64, CesrSignature: e.CesrSignature,
		})
	}
	oobi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"aid": contact.aid, "public_key": contact.pubs[1], "alias": "moved org", "kel": events,
		})
	}))
	t.Cleanup(oobi.Close)

	// The contact's witness holds its newest signed record, signed by the key
	// the log put in force at the rotation.
	record := signedRecord(t, contact.aid, "https://moved.example.com:443", time.Minute, contact.seeds[1])
	wit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/witness/endpoint/"+contact.aid {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"record": recordObject(record)})
	}))
	t.Cleanup(wit.Close)

	s := witnessWithStore(t)
	s.KeriDriver = keriengine.New()
	if err := s.DataStore.SaveContact(store.ContactRecord{AID: witnessName, OobiURL: wit.URL + "/public/oobi/" + witnessName}); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]string{"oobi_url": oobi.URL + "/public/oobi/" + contact.aid})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/contacts/resolve", bytes.NewReader(body))
	s.handleResolveOobiContact(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("resolve answered %d: %s", rec.Code, rec.Body.String())
	}
	kept, err := s.DataStore.GetContactKEL(contact.aid)
	if err != nil || kept == nil || !kept.KelVerified {
		t.Fatalf("the resolved log was not kept as verified: %+v, %v", kept, err)
	}
	// Whatever fields a stored entry carries beside its bytes (the store now derives
	// them from the verified bytes), recovery reads the witnesses from the bytes.

	found, err := s.RecoverContactEndpoint(contact.aid)
	if err != nil {
		t.Fatalf("a contact stored the normal way was not recoverable: %v", err)
	}
	if found.Origin != "https://moved.example.com:443" || found.FoundVia != witnessName {
		t.Fatalf("got %+v", found)
	}
}
