package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/keriengine"
	"identity-agent-core/store"
	"identity-agent-core/witness"
)

// A computer asking to act for an identity checks who is actually there.
//
// Everything else in this area is the Identity Agent satisfying itself about
// the machine. This runs the other way, and without it the machine wrote down
// whatever identifier it was told — believed by every later launch, because
// that is what a recorded answer is for.
func TestAnIdentityElsewhereIsCheckedAgainstItsPublishedHistory(t *testing.T) {
	ask := func(t *testing.T, s *CoreServer, body string) verifyIdentityResponse {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/verify/identity-elsewhere",
			strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
		rec := httptest.NewRecorder()
		s.handleVerifyAnIdentityElsewhere(rec, req)
		var out verifyIdentityResponse
		json.NewDecoder(rec.Body).Decode(&out)
		return out
	}

	t.Run("an address publishing nothing is not verified", func(t *testing.T) {
		s := agentWithNoIdentity(t)
		s.KeriDriver = keriengine.New()
		s.engineSigns()
		empty := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`[]`)) }))
		defer empty.Close()

		out := ask(t, s, `{"aid":"ESOMEBODY","oobi_url":"`+empty.URL+`"}`)
		if out.Verified {
			t.Fatal("an address that published no key history was accepted")
		}
		if out.Why == "" {
			t.Error("no reason, which somebody cannot act on")
		}
	})

	t.Run("an address nothing answers at is not verified", func(t *testing.T) {
		s := agentWithNoIdentity(t)
		s.KeriDriver = keriengine.New()
		s.engineSigns()
		out := ask(t, s, `{"aid":"ESOMEBODY","oobi_url":"http://127.0.0.1:9/nope"}`)
		if out.Verified {
			t.Fatal("an unreachable address was accepted")
		}
	})

	t.Run("a computer with no engine says so rather than refusing", func(t *testing.T) {
		// Different answers. "Do not trust that" and "this computer cannot
		// tell" lead to the same caution and to different words, and a caller
		// that could not distinguish them would report the wrong one.
		s := agentWithNoIdentity(t)
		s.KeriDriver = nil
		req := httptest.NewRequest(http.MethodPost, "/api/verify/identity-elsewhere",
			strings.NewReader(`{"aid":"ESOMEBODY","oobi_url":"https://x.test/oobi"}`))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
		rec := httptest.NewRecorder()
		s.handleVerifyAnIdentityElsewhere(rec, req)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("expected this computer to say it cannot check, got %d %s",
				rec.Code, rec.Body.String())
		}
	})

	t.Run("naming no identity or no address is refused", func(t *testing.T) {
		s := agentWithNoIdentity(t)
		s.KeriDriver = keriengine.New()
		s.engineSigns()
		for _, body := range []string{
			`{"aid":"","oobi_url":"https://x.test/oobi"}`,
			`{"aid":"ESOMEBODY","oobi_url":""}`,
		} {
			req := httptest.NewRequest(http.MethodPost, "/api/verify/identity-elsewhere",
				strings.NewReader(body))
			req.RemoteAddr = "127.0.0.1:1234"
			req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
			rec := httptest.NewRecorder()
			s.handleVerifyAnIdentityElsewhere(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s was not refused: %d", body, rec.Code)
			}
		}
	})
}

// The witnesses an organisation's key log names come back with the answer, read
// from the log that was just verified, each at the address this core holds for
// it. An app that joins an organisation keeps them to find it again if it moves.
func TestAnIdentityElsewhereAnswersWithTheWitnessesItsLogNames(t *testing.T) {
	w := newStandInWitness(t)
	prior := witness.BootstrapWitnesses
	witness.BootstrapWitnesses = func() []witness.BootstrapWitness {
		return []witness.BootstrapWitness{{AID: w.key, WitnessKey: w.key, URL: w.URL, Operator: "tests"}}
	}
	t.Cleanup(func() { witness.BootstrapWitnesses = prior })

	// The identity being checked is a real one whose inception names the witness.
	elsewhere := adoptingOwner(t)
	aid, _, _, err := elsewhere.mintPairwise("check")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := elsewhere.DataStore.GetEvents(aid)
	if err != nil || len(stored) == 0 {
		t.Fatalf("no events for the identity: %v", err)
	}
	served := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		json.NewEncoder(rw).Encode(map[string]any{"kel": stored})
	}))
	defer served.Close()

	// The core doing the checking, which knows where that witness is reached.
	s := adoptingOwner(t)
	// A local address is reached only where the owner recorded a contact there.
	if err := s.DataStore.SaveContact(store.ContactRecord{AID: aid, OobiURL: served.URL}); err != nil {
		t.Fatal(err)
	}
	ask := func(aid, oobi string) verifyIdentityResponse {
		body, _ := json.Marshal(map[string]string{"aid": aid, "oobi_url": oobi})
		req := httptest.NewRequest(http.MethodPost, "/api/verify/identity-elsewhere",
			bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
		rec := httptest.NewRecorder()
		s.handleVerifyAnIdentityElsewhere(rec, req)
		var out verifyIdentityResponse
		json.NewDecoder(rec.Body).Decode(&out)
		return out
	}

	out := ask(aid, served.URL)
	if !out.Verified {
		t.Fatalf("a real key history was not verified: %s", out.Why)
	}
	if len(out.Witnesses) == 0 {
		t.Fatal("the witnesses the verified log names were not returned")
	}
	for _, n := range out.Witnesses {
		if n.Key != w.key {
			t.Errorf("a witness the log does not name came back: %+v", n)
		}
		if !strings.HasPrefix(n.URL, "http") {
			t.Errorf("the named witness came back with no address this core holds: %+v", n)
		}
	}

	// Nothing is claimed for a history that does not check out: the same
	// witnesses served under another identifier come back unverified and bare.
	wrong := ask("ENotTheOwnerOfThatLog", served.URL)
	if wrong.Verified || len(wrong.Witnesses) != 0 {
		t.Fatalf("a log that does not belong to the identifier gave leads: %+v", wrong)
	}
}
