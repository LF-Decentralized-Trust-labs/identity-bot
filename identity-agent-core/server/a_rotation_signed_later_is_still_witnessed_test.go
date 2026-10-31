package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/store"
	"identity-agent-core/witness"
)

// An identity whose key lives on a device has each event added unsigned and
// signed by the device afterwards. A witness is never sent an unsigned event,
// so an establishment event signed after the fact reaches the witnesses only
// if recording its signature sends it. And the key log says which events are
// still unsigned, so a device that lost its connection between the two steps
// can tell what it still owes.
func TestARotationSignedLaterIsStillWitnessed(t *testing.T) {
	keys := make([]ed25519.PrivateKey, 1)
	names := make([]string, 1)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keys[0], names[0] = priv, iacrypto.NonTransferableAIDQB64(pub)
	s, _ := foundedWith(t, agentWithDerivedIdentity(t), names, 1)
	s.localOwnerSecret = testOwnerSecret
	sq := s.DataStore.(*store.SQLiteStore)
	s.WitnessService = witness.NewService(witness.NewSQLiteStore(sq.DB()), sq, s.KeriDriver, witness.BackendDesktop)
	s.DataStore.SaveContact(store.ContactRecord{AID: "EWitness0", OobiURL: "http://w0.test", Status: "active", IsWitness: true})
	s.WitnessService.Store.SaveContactMeta(witness.ContactMeta{ContactAID: "EWitness0", WitnessKey: names[0], IsCommercial: true})
	var mu sync.Mutex
	var sent []map[string]any
	s.WitnessService.PostEvent = func(_ context.Context, _ string, body []byte) (map[string]interface{}, error) {
		var req map[string]any
		json.Unmarshal(body, &req)
		mu.Lock()
		sent = append(sent, req)
		mu.Unlock()
		return nil, fmt.Errorf("offline")
	}
	s.router = s.buildRouter("")
	id, _ := s.DataStore.GetIdentity()
	events, _ := s.DataStore.GetEvents(id.AID)
	founding := events[0]
	sig := founding.CesrSignature
	if sig == "" {
		t.Fatal("the founding event is not signed to begin with")
	}

	// Stranded: the event was added and its signature never arrived. Written
	// directly, because the store never blanks a signature it holds.
	if _, err := sq.DB().Exec(`UPDATE kel SET cesr_signature = '' WHERE aid = ? AND seq_num = 0`, id.AID); err != nil {
		t.Fatal(err)
	}
	signedFlags := func() []bool {
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, local("GET", "/api/kel?name="+id.AID, ""))
		var out struct {
			Signed []bool `json:"signed"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out.Signed
	}
	if got := signedFlags(); len(got) == 0 || got[0] {
		t.Fatalf("the key log does not say its founding event is unsigned: %v", got)
	}

	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, local("POST", "/api/events/signature",
		`{"aid":"`+id.AID+`","sequence_number":0,"cesr_signature":"`+sig+`"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("recording the signature was answered %d %s", rec.Code, rec.Body.String())
	}
	if got := signedFlags(); len(got) == 0 || !got[0] {
		t.Fatalf("the key log does not say its founding event is now signed: %v", got)
	}
	for i := 0; i < 100; i++ {
		mu.Lock()
		n := len(sent)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, req := range sent {
		if req["aid"] == id.AID && req["cesr_signature"] == sig {
			return
		}
	}
	t.Fatalf("the newly signed founding event was not sent to the witnesses: %v", sent)
}
