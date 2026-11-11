package server

import (
	"net/http"
	"testing"
)

// answerEmptyFor makes the stand-in answer an identifier it holds nothing for
// the way the production witnesses do: HTTP 200 {"count":0,"kel":null}.
func answerEmptyFor(w *standInWitness) {
	w.Config.Handler.(*http.ServeMux).HandleFunc("/witness/kel/EFresh", func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write([]byte(`{"count":0,"kel":null}`))
	})
}

func freshClaim(w *standInWitness) []map[string]interface{} {
	return []map[string]interface{}{
		{"t": "icp", "i": "EFresh", "s": "0", "d": "EFreshInception", "b": []interface{}{w.key}},
	}
}

// A designated witness that answers 200 and holds nothing for the identifier
// confirms nothing.
func TestAWitnessAnsweringWithAnEmptyLogDoesNotCorroborate(t *testing.T) {
	w := newStandInWitness(t)
	answerEmptyFor(w)
	got := agentWithNoIdentity(t).askTheWitnesses("EFresh", freshClaim(w))
	if got.Corroborated() {
		t.Fatalf("a witness that holds nothing corroborated the claim: %+v", got)
	}
	if got.Asked != 1 || got.Empty != 1 || got.Held != 0 || got.Failed != 0 || got.Contradicted {
		t.Fatalf("counts %+v, want one answered, one empty, none held or failed", got)
	}
}

// An empty array is the same answer as null.
func TestAWitnessAnsweringWithAnEmptyArrayDoesNotCorroborate(t *testing.T) {
	w := newStandInWitness(t)
	w.held["EFresh"] = []map[string]interface{}{}
	got := agentWithNoIdentity(t).askTheWitnesses("EFresh", freshClaim(w))
	if got.Corroborated() || got.Empty != 1 {
		t.Fatalf("an empty log corroborated: %+v", got)
	}
}

// A witness holding the events, same digests, corroborates and is counted held.
func TestAWitnessHoldingTheEventsIsCountedHeld(t *testing.T) {
	w := newStandInWitness(t)
	claim := freshClaim(w)
	w.held["EFresh"] = claim
	got := agentWithNoIdentity(t).askTheWitnesses("EFresh", claim)
	if !got.Corroborated() || got.Held != 1 || got.Empty != 0 {
		t.Fatalf("a witness holding the claimed history did not corroborate: %+v", got)
	}
}

// Same sequence, different digest: a fork, and a contradiction.
func TestAWitnessHoldingADifferentEventContradicts(t *testing.T) {
	w := newStandInWitness(t)
	claim := freshClaim(w)
	other := []map[string]interface{}{{"t": "icp", "i": "EFresh", "s": "0", "d": "EOther", "b": []interface{}{w.key}}}
	w.held["EFresh"] = other
	got := agentWithNoIdentity(t).askTheWitnesses("EFresh", claim)
	if !got.Contradicted || got.Corroborated() {
		t.Fatalf("a different event at the same place was not a contradiction: %+v", got)
	}
}

// Some of the history, but less than claimed, does not corroborate it.
func TestAWitnessHoldingLessThanClaimedDoesNotCorroborate(t *testing.T) {
	w := newStandInWitness(t)
	claim := append(freshClaim(w), map[string]interface{}{"t": "rot", "i": "EFresh", "s": "1", "d": "ERot"})
	w.held["EFresh"] = claim[:1]
	got := agentWithNoIdentity(t).askTheWitnesses("EFresh", claim)
	if got.Corroborated() || got.Behind != 1 || got.Contradicted {
		t.Fatalf("a witness behind the claim corroborated it: %+v", got)
	}
}
