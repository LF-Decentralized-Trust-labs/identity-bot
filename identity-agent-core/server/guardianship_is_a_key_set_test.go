package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/store"

	"github.com/go-chi/chi/v5"
)

func createGuardianship(t *testing.T, s *CoreServer, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleCreateGuardianship(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	return w
}

// Guardianship is a multi-signature on the dependent's own identifier: the
// record keeps that identifier and the keys of its key set, and no identifier
// of a guardian.
func TestAGuardianshipKeepsTheKeySetAndNoGuardiansIdentifier(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	w := createGuardianship(t, s, `{"type":"minor_child","dependent_name":"Sam","dependent_aid":"EDep","hosting_type":"cloud",
		"multisig_participants":[{"public_key":"DkeyOne","role":"guardian"},{"public_key":"DkeyTwo","role":"co_guardian"}],"multisig_threshold":2}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	for _, gone := range []string{"guardian_aid", "delegated_aid_prefix", "co_guardians"} {
		if _, ok := out[gone]; ok {
			t.Errorf("the record still carries %s", gone)
		}
	}
	id, _ := s.DataStore.GetIdentity()
	if strings.Contains(w.Body.String(), id.AID) && !strings.Contains(w.Body.String(), "credential_said") {
		t.Error("the guardian's own identifier is in the record")
	}
	rec, _ := s.DataStore.GetGuardianship(out["id"].(string))
	if rec == nil || len(rec.MultisigParticipants) != 2 || rec.MultisigThreshold != 2 || rec.DependentAID != "EDep" {
		t.Fatalf("the key set did not round-trip: %+v", rec)
	}
	if rec.MultisigParticipants[0].PublicKey != "DkeyOne" || rec.MultisigParticipants[1].Role != "co_guardian" {
		t.Errorf("%+v", rec.MultisigParticipants)
	}
}

// A request that names a guardian's identifier, or a delegation, is refused and
// nothing is stored: a guardian's identifier is never kept.
func TestAGuardiansIdentifierOrADelegationIsRefused(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	for _, f := range []string{`"guardian_aid":"EGuardian"`, `"delegated_aid_prefix":"EDelegated"`, `"co_guardians":["EOther"]`} {
		w := createGuardianship(t, s, `{"type":"minor_child","dependent_name":"Sam","hosting_type":"cloud",`+f+`}`)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", f, w.Code)
		}
	}
	if all, _ := s.DataStore.GetGuardianships(); len(all) != 0 {
		t.Errorf("%d guardianships stored from refused requests", len(all))
	}
}

// A key set that is not one is refused.
func TestAKeySetThatIsNotOneIsRefused(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	for name, f := range map[string]string{
		"a blank key":              `"multisig_participants":[{"public_key":"","role":"guardian"}],"multisig_threshold":1`,
		"an unknown role":          `"multisig_participants":[{"public_key":"Dk","role":"delegator"}],"multisig_threshold":1`,
		"a repeated key":           `"multisig_participants":[{"public_key":"Dk","role":"guardian"},{"public_key":"Dk","role":"court"}],"multisig_threshold":1`,
		"a threshold too big":      `"multisig_participants":[{"public_key":"Dk","role":"guardian"}],"multisig_threshold":2`,
		"a negative threshold":     `"multisig_participants":[],"multisig_threshold":-1`,
		"a threshold with no keys": `"multisig_threshold":1`,
	} {
		w := createGuardianship(t, s, `{"type":"minor_child","dependent_name":"Sam","hosting_type":"cloud",`+f+`}`)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
}

// An update cannot put a guardian's identifier back.
func TestAnUpdateCannotNameAGuardiansIdentifier(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	rec := store.GuardianshipRecord{ID: "g1", Type: "minor_child", DependentName: "Sam", Status: "active"}
	if err := s.DataStore.SaveGuardianship(rec); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{`"guardian_aid":"E1"`, `"delegated_aid_prefix":"E2"`, `"co_guardians":["E3"]`} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{`+f+`}`))
		r = withURLParam(r, "id", "g1")
		s.handleUpdateGuardianship(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", f, w.Code)
		}
	}
}

func withURLParam(r *http.Request, k, v string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(k, v)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}
