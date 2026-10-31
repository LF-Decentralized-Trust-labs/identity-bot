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
	found := func(t *testing.T, ownKey bool) map[string]any {
		t.Helper()
		s := witnessWithSeed(t, 1)
		s.KeriDriver = keriengine.New()
		s.engineSigns()
		body := ourFounding(t, s)
		if !ownKey {
			// Keys from another seed: held somewhere else, a phone, say.
			body = ourFounding(t, witnessWithSeed(t, 7))
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

	own := found(t, true)
	if n, _ := own["n"].([]any); len(n) != 2 || own["_pq"] != true {
		t.Fatalf("a founding with this agent's own key does not commit to its post-quantum key: %v", own["n"])
	}
	if a, _ := own["a"].([]any); len(a) != 1 {
		t.Fatalf("a founding with this agent's own key does not anchor its messaging keys: %v", own["a"])
	}

	elsewhere := found(t, false)
	if n, _ := elsewhere["n"].([]any); len(n) != 1 || elsewhere["_pq"] != false {
		t.Fatalf("a founding with a key held elsewhere commits to a key of this agent's: %v", elsewhere["n"])
	}
	if a, _ := elsewhere["a"].([]any); len(a) != 0 {
		t.Fatalf("a founding with a key held elsewhere anchors this agent's messaging keys: %v", elsewhere["a"])
	}
}
