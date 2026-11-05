package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/keriengine"
	"identity-agent-core/store"
)

// Founding records where the keys live, and says so when asked who this is.
func TestFoundingRecordsWhereTheKeysLive(t *testing.T) {
	aMachineThatMayFound(t)
	s := witnessWithSeed(t, 1)
	s.KeriDriver = keriengine.New()
	s.engineSigns()
	b, _ := json.Marshal(ourFounding(t, s))
	rec := httptest.NewRecorder()
	s.buildRouter().ServeHTTP(rec, local("POST", "/api/inception", string(b)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("founding was answered %d %s", rec.Code, rec.Body.String())
	}
	got, err := s.DataStore.GetIdentity()
	if err != nil || got == nil || got.KeysLive != store.KeysLocal {
		t.Fatalf("a founded identity did not record where its keys live: %+v %v", got, err)
	}
	rec = httptest.NewRecorder()
	s.buildRouter().ServeHTTP(rec, local("GET", "/api/identity", ""))
	var out IdentityResponse
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out.KeysLive != store.KeysLocal {
		t.Fatalf("GET /api/identity does not say where the keys live: %s", rec.Body.String())
	}
}
