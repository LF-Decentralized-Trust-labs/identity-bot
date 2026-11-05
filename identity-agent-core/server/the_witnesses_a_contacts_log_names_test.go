package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/store"
	"identity-agent-core/witness"

	"github.com/go-chi/chi/v5"
)

// An app that cannot reach an organisation reads the witnesses its verified
// key log named, with the addresses this core holds, from the core.
func TestTheWitnessesAContactsLogNamesAreReadFromTheCore(t *testing.T) {
	w := newStandInWitness(t)
	s := agentWithNoIdentity(t)
	sq := s.DataStore.(*store.SQLiteStore)
	s.WitnessService = witness.NewService(witness.NewSQLiteStore(sq.DB()), sq, nil, witness.BackendDesktop)
	ask := func(aid string) (int, []namedWitness) {
		req := httptest.NewRequest(http.MethodGet, "/api/contacts/"+aid+"/witnesses", nil)
		rc := chi.NewRouteContext()
		rc.URLParams.Add("aid", aid)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))
		rec := httptest.NewRecorder()
		s.handleGetWitnessesNamedByContact(rec, req)
		var out struct {
			Witnesses []namedWitness `json:"witnesses"`
		}
		_ = json.NewDecoder(rec.Body).Decode(&out)
		return rec.Code, out.Witnesses
	}
	kel := []map[string]interface{}{
		{"t": "icp", "i": "EOrg", "s": "0", "b": []interface{}{w.key}},
	}
	if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: "EOrg", KEL: kel, KelVerified: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: "EUnverified", KEL: kel, KelVerified: false}); err != nil {
		t.Fatal(err)
	}

	code, got := ask("EOrg")
	if code != 200 || len(got) != 1 || got[0].Key != w.key || !strings.HasPrefix(got[0].URL, "http") {
		t.Fatalf("the named witness was not returned with its address: %d %+v", code, got)
	}
	if code, _ := ask("EUnverified"); code != http.StatusNotFound {
		t.Fatalf("a log this core did not verify was used: %d", code)
	}
	if code, _ := ask("ENobody"); code != http.StatusNotFound {
		t.Fatalf("an identity with no stored log answered %d", code)
	}
}
