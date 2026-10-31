package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/keriengine"
)

// A founding carries this agent's messaging keys and post-quantum commitment
// only when the identity's key is this agent's own. For a key held somewhere
// else they would be this machine's keys in somebody else's identity: the
// post-quantum commitment alone could rotate it. Then the founding commits to
// the next key asked for and nothing else, and still succeeds.
func TestAFoundingCarriesOnlyTheKeysItShould(t *testing.T) {
	aMachineThatMayFound(t)
	found := func(t *testing.T, ownKey, ownNext bool) map[string]any {
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
		b, _ := json.Marshal(body)
		rec := httptest.NewRecorder()
		s.buildRouter("").ServeHTTP(rec, local("POST", "/api/inception", string(b)))
		if rec.Code != http.StatusCreated {
			t.Fatalf("founding was answered %d %s", rec.Code, rec.Body.String())
		}
		var out struct {
			RawBytesB64          string `json:"raw_bytes_b64"`
			PostQuantumCommitted bool   `json:"post_quantum_committed"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		raw, _ := base64.StdEncoding.DecodeString(out.RawBytesB64)
		var ev map[string]any
		json.Unmarshal(raw, &ev)
		ev["_pq"] = out.PostQuantumCommitted
		return ev
	}

	own := found(t, true, true)
	if n, _ := own["n"].([]any); len(n) != 2 || own["_pq"] != true {
		t.Fatalf("a founding with this agent's own key does not commit to its post-quantum key: %v", own["n"])
	}
	if a, _ := own["a"].([]any); len(a) != 1 {
		t.Fatalf("a founding with this agent's own key does not anchor its messaging keys: %v", own["a"])
	}

	for _, c := range []struct {
		name            string
		ownKey, ownNext bool
	}{
		{"a key held elsewhere", false, false},
		// This agent's first key and somebody else's next key: the chain is not
		// this agent's, so its own keys are not added.
		{"this agent's key committing to somebody else's next key", true, false},
		{"somebody else's key committing to this agent's next key", false, true},
	} {
		ev := found(t, c.ownKey, c.ownNext)
		if n, _ := ev["n"].([]any); len(n) != 1 || ev["_pq"] != false {
			t.Fatalf("a founding with %s commits to a key of this agent's: %v", c.name, ev["n"])
		}
		if a, _ := ev["a"].([]any); len(a) != 0 {
			t.Fatalf("a founding with %s anchors this agent's messaging keys: %v", c.name, ev["a"])
		}
	}
}
