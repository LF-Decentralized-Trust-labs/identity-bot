package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/witness"
)

// Asking somebody other than the claimant whether a history is complete.
//
// These stand up a real witness rather than a stub that returns yes, because
// the whole question is what a SECOND party holds — a stand-in that agrees with
// whatever it is shown would pass every test here while testing nothing.

// standInWitness serves the three things a witness has to answer for this to
// work: who it is, so it can be designated at all; the events it is sent; and
// its copy of an identity's log, which is the check.
type standInWitness struct {
	*httptest.Server
	mu  sync.Mutex
	key string
	// held is what this witness will say it holds, per identity. Set by a test
	// to stand for a history the claimant did not show.
	held map[string][]map[string]interface{}
}

func newStandInWitness(t *testing.T) *standInWitness {
	t.Helper()
	w := &standInWitness{ // A well-formed non-transferable identifier. It has to be: the engine
		// refuses to designate anything else, because a receipt from a
		// transferable identifier could not be checked without first resolving
		// that witness's own key log.
		key: iacrypto.NonTransferableAIDQB64(bytes.Repeat([]byte{7}, 32)), held: map[string][]map[string]interface{}{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(rw http.ResponseWriter, r *http.Request) {
		json.NewEncoder(rw).Encode(map[string]any{"service_aid": w.key})
	})
	mux.HandleFunc("/witness/event", func(rw http.ResponseWriter, r *http.Request) {
		// Record what it is sent, as a real witness does. A stand-in that
		// accepted events and remembered nothing would report every identity as
		// unknown, and the honest path would look identical to an attack.
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		ev, _ := body["event"].(map[string]interface{})
		if ev == nil {
			if raw, ok := body["raw_event"].(string); ok {
				var parsed map[string]interface{}
				if json.Unmarshal([]byte(raw), &parsed) == nil {
					ev = parsed
				}
			}
		}
		if aid, _ := ev["i"].(string); aid != "" {
			w.mu.Lock()
			w.held[aid] = append(w.held[aid], ev)
			w.mu.Unlock()
		}
		json.NewEncoder(rw).Encode(map[string]any{"ok": true})
	})
	mux.HandleFunc("/witness/kel/", func(rw http.ResponseWriter, r *http.Request) {
		aid := r.URL.Path[len("/witness/kel/"):]
		w.mu.Lock()
		kel, ok := w.held[aid]
		w.mu.Unlock()
		if !ok {
			http.NotFound(rw, r)
			return
		}
		json.NewEncoder(rw).Encode(map[string]any{"aid": aid, "kel": kel, "count": len(kel)})
	})
	w.Server = httptest.NewServer(mux)
	t.Cleanup(w.Close)

	prior := witness.BootstrapWitnesses
	witness.BootstrapWitnesses = func() []witness.BootstrapWitness {
		return []witness.BootstrapWitness{{
			AID: "EStandInWitness", WitnessKey: w.key, URL: w.URL, Operator: "tests",
		}}
	}
	t.Cleanup(func() { witness.BootstrapWitnesses = prior })
	return w
}

// THE CASE THIS EXISTS FOR. A claimant shows a log with the last event removed
// and signs with the key that log puts in force. Everything about the claim
// verifies; the identity has already moved on.
func TestAHistoryWithARotationWithheldIsRefused(t *testing.T) {
	w := newStandInWitness(t)
	s := agentWithNoIdentity(t)

	presented := []map[string]interface{}{
		{"t": "icp", "i": "EClaimant", "s": "0", "b": []interface{}{w.key}},
	}
	// The witness saw a rotation the claim did not show.
	w.held["EClaimant"] = []map[string]interface{}{
		{"t": "icp", "i": "EClaimant", "s": "0", "b": []interface{}{w.key}},
		{"t": "rot", "i": "EClaimant", "s": "1"},
	}

	got := s.askTheWitnesses("EClaimant", presented)
	if !got.Contradicted {
		t.Fatalf("a witness holding a longer history than the claim showed did not "+
			"contradict it: %+v", got)
	}
	if got.Why == "" {
		t.Error("contradicted, but with no reason a refusal could quote")
	}
}

// The same history, whole. It must not be refused.
//
// Without this a check that contradicted everything would pass the test above
// and make every honest claim fail.
func TestAWholeHistoryIsCorroborated(t *testing.T) {
	w := newStandInWitness(t)
	s := agentWithNoIdentity(t)

	kel := []map[string]interface{}{
		{"t": "icp", "i": "EClaimant", "s": "0", "b": []interface{}{w.key}},
	}
	w.held["EClaimant"] = kel

	got := s.askTheWitnesses("EClaimant", kel)
	if got.Contradicted {
		t.Fatalf("an honest, complete history was contradicted: %s", got.Why)
	}
	if !got.Corroborated() {
		t.Fatalf("a reachable witness holding exactly this history did not corroborate it: %+v", got)
	}
}

// A witness that cannot be reached leaves the history uncorroborated. It does
// NOT mean the claim is refuted — conflating the two makes every network fault
// look like an attack.
func TestAnUnreachableWitnessIsNotAContradiction(t *testing.T) {
	w := newStandInWitness(t)
	s := agentWithNoIdentity(t)
	kel := []map[string]interface{}{
		{"t": "icp", "i": "EClaimant", "s": "0", "b": []interface{}{w.key}},
	}
	w.Close() // down, as far as anyone claiming is concerned

	got := s.askTheWitnesses("EClaimant", kel)
	if got.Contradicted {
		t.Fatal("an unreachable witness was treated as refuting the claim")
	}
	if got.Corroborated() {
		t.Fatal("a history nobody could confirm was reported as corroborated")
	}
	if got.Designated != 1 {
		t.Errorf("the log names one witness; got %d", got.Designated)
	}
}

// An identity that named no witnesses can never be corroborated, and says so
// rather than appearing to pass.
func TestAnIdentityThatNamedNoWitnessesIsNotCorroborated(t *testing.T) {
	s := agentWithNoIdentity(t)
	got := s.askTheWitnesses("EClaimant", []map[string]interface{}{
		{"t": "icp", "i": "EClaimant", "s": "0"},
	})
	if got.Corroborated() || got.Designated != 0 {
		t.Fatalf("an identity with no designated witnesses was reported as %+v", got)
	}
}

// The policy: where a machine cannot ask, what it does depends on whether being
// unable to ask is meaningful.
func TestOnlyAMachineThatCanAlwaysReachAWitnessRefusesForNotReaching(t *testing.T) {
	s := agentWithNoIdentity(t)

	resetLocalPairingOfferForTest()
	if !s.mustBeCorroborated() {
		t.Fatal("a machine somebody else set up does not require corroboration — it was " +
			"reached by a provisioning host, so being unable to reach a witness is a signal")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/pairing/offer-this-computer", nil)
	req.RemoteAddr = "127.0.0.1:5050"
	s.handleOfferThisComputer(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("could not offer the computer: %s", rec.Body.String())
	}
	if s.mustBeCorroborated() {
		t.Fatal("a computer offered from its own screen requires corroboration, so one being " +
			"set up with no working network could never be paired — which is the ordinary case")
	}
	t.Cleanup(resetLocalPairingOfferForTest)
}

// A log arrives in two shapes, and reading only one silently disables the check.
//
// A witness serves parsed events, with the fields at the top level. This
// agent's own store keeps records, with the event as text under event_json.
// The first version of this read only the parsed shape, so every claim carrying
// a stored log came back "0 witnesses named" — not an error, not a refusal,
// just a check that quietly established nothing. That is worse than a bug that
// fails, so both shapes are asserted.
func TestWitnessKeysAreFoundInEitherShapeOfLog(t *testing.T) {
	const key = "BAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH"

	parsed := []map[string]interface{}{
		{"t": "icp", "i": "EClaimant", "s": "0", "b": []interface{}{key}},
	}
	stored := []map[string]interface{}{
		{
			"event_type":      "icp",
			"sequence_number": 0,
			"event_json":      `{"t":"icp","i":"EClaimant","s":"0","b":["` + key + `"]}`,
		},
	}

	for name, kel := range map[string][]map[string]interface{}{
		"as a witness serves it": parsed,
		"as the store keeps it":  stored,
	} {
		got := witnessKeysIn(kel)
		if len(got) != 1 || got[0] != key {
			t.Errorf("%s: the designated witness was not found (%v), so nothing would be "+
				"asked and the history would pass unchecked", name, got)
		}
	}
}
