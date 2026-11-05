package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/keriengine"
)

// /api/inception founds only with keys this agent derives itself, and signs the
// founding itself. A key held somewhere else is founded by the app that holds
// it, through the prepare and commit routes, so this route answers 409
// key_not_held_here and stores nothing: a founding this agent cannot sign would
// enter the key log unsigned (ADR-061).
func TestAFoundingCarriesOnlyTheKeysItShould(t *testing.T) {
	aMachineThatMayFound(t)
	found := func(t *testing.T, ownKey, ownNext bool, extra map[string]any) (*CoreServer, *httptest.ResponseRecorder) {
		t.Helper()
		s := witnessWithSeed(t, 1)
		s.KeriDriver = keriengine.New()
		s.engineSigns()
		body := ourFounding(t, s)
		elsewhere := ourFounding(t, witnessWithSeed(t, 7)) // keys from another seed: a phone, say
		if !ownKey {
			body["public_key"] = elsewhere["public_key"]
		}
		if !ownNext {
			body["next_public_key"] = elsewhere["next_public_key"]
		}
		for k, v := range extra {
			body[k] = v
		}
		b, _ := json.Marshal(body)
		rec := httptest.NewRecorder()
		s.buildRouter().ServeHTTP(rec, local("POST", "/api/inception", string(b)))
		return s, rec
	}

	_, rec := found(t, true, true, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("founding was answered %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		RawBytesB64          string `json:"raw_bytes_b64"`
		PostQuantumCommitted bool   `json:"post_quantum_committed"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	raw, _ := base64.StdEncoding.DecodeString(out.RawBytesB64)
	var own map[string]any
	json.Unmarshal(raw, &own)
	if n, _ := own["n"].([]any); len(n) != 2 || !out.PostQuantumCommitted {
		t.Fatalf("a founding with this agent's own key does not commit to its post-quantum key: %v", own["n"])
	}
	if a, _ := own["a"].([]any); len(a) != 1 {
		t.Fatalf("a founding with this agent's own key does not anchor its messaging keys: %v", own["a"])
	}

	for _, c := range []struct {
		name            string
		ownKey, ownNext bool
		extra           map[string]any
	}{
		{"a key held elsewhere", false, false, nil},
		// This agent's first key and somebody else's next key: the chain is not
		// this agent's, so it neither founds with it nor adds its own keys.
		{"this agent's key committing to somebody else's next key", true, false, nil},
		{"somebody else's key committing to this agent's next key", false, true, nil},
		// The signature is not this agent's to vouch for and is not stored.
		{"a key held elsewhere with a signature nobody checked", false, false,
			map[string]any{"cesr_signature": "AAjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunk"}},
	} {
		s, rec := found(t, c.ownKey, c.ownNext, c.extra)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "key_not_held_here") ||
			!strings.Contains(rec.Body.String(), "/api/events/prepare") || !strings.Contains(rec.Body.String(), "/api/events/commit") {
			t.Fatalf("a founding with %s was answered %d %s, not key_not_held_here naming the prepare and commit routes",
				c.name, rec.Code, rec.Body.String())
		}
		if id, _ := s.DataStore.GetIdentity(); id != nil {
			t.Fatalf("a founding with %s left an identity behind: %+v", c.name, id)
		}
	}
}
