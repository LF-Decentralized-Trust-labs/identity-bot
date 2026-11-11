package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
)

// withBytes presents events as a verifier receives them: each record carries the
// event's published bytes, which is all a verdict on the claim covers.
func withBytes(events ...map[string]interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(events))
	for _, ev := range events {
		raw, _ := json.Marshal(ev)
		out = append(out, map[string]interface{}{"raw_bytes_b64": base64.StdEncoding.EncodeToString(raw)})
	}
	return out
}

// answerEmptyFor makes the stand-in answer an identifier it holds nothing for
// the way the production witnesses do: HTTP 200 {"count":0,"kel":null}.
func answerEmptyFor(w *standInWitness) {
	w.Config.Handler.(*http.ServeMux).HandleFunc("/witness/kel/EFresh", func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write([]byte(`{"count":0,"kel":null}`))
	})
}

func freshClaim(w *standInWitness) []map[string]interface{} {
	return withBytes(map[string]interface{}{"t": "icp", "i": "EFresh", "s": "0", "d": "EFreshInception", "b": []interface{}{w.key}})
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
	claim := append(freshClaim(w), withBytes(map[string]interface{}{"t": "rot", "i": "EFresh", "s": "1", "d": "ERot"})...)
	w.held["EFresh"] = claim[:1]
	got := agentWithNoIdentity(t).askTheWitnesses("EFresh", claim)
	if got.Corroborated() || got.Behind != 1 || got.Contradicted {
		t.Fatalf("a witness behind the claim corroborated it: %+v", got)
	}
}

// A log whose verified bytes are a fork cannot borrow the witness's digest by
// carrying it as an unverified top-level "d" beside the bytes.
func TestATopLevelDigestBesideForkedBytesDoesNotCorroborate(t *testing.T) {
	w := newStandInWitness(t)
	w.held["EFresh"] = []map[string]interface{}{
		{"t": "icp", "i": "EFresh", "s": "0", "d": "EFreshInception", "b": []interface{}{w.key}}}
	presented := withBytes(map[string]interface{}{"t": "icp", "i": "EFresh", "s": "0", "d": "EForkedInception", "b": []interface{}{w.key}})
	presented[0]["d"] = "EFreshInception" // not covered by any verification
	got := agentWithNoIdentity(t).askTheWitnesses("EFresh", presented)
	if got.Corroborated() || got.Held != 0 {
		t.Fatalf("forked bytes corroborated by forging a top-level d: %+v", got)
	}
	if !got.Contradicted {
		t.Fatalf("the fork was not seen as a different event: %+v", got)
	}
}

// A log without verified bytes is not corroborated at all.
func TestAPresentedLogWithoutBytesIsNotCorroborated(t *testing.T) {
	w := newStandInWitness(t)
	ev := map[string]interface{}{"t": "icp", "i": "EFresh", "s": "0", "d": "EFreshInception", "b": []interface{}{w.key}}
	w.held["EFresh"] = []map[string]interface{}{ev}
	got := agentWithNoIdentity(t).askTheWitnesses("EFresh", []map[string]interface{}{ev})
	if got.Corroborated() || got.Asked != 0 {
		t.Fatalf("a log with no verified bytes was corroborated: %+v", got)
	}
}

// A witness's copy with no readable digest is not a copy that holds the event:
// the fail-open holdsDigests closes.
func TestAWitnessCopyWithNoDigestIsBehindNotHeld(t *testing.T) {
	w := newStandInWitness(t)
	w.held["EFresh"] = []map[string]interface{}{{"t": "icp", "i": "EFresh", "s": "0", "b": []interface{}{w.key}}}
	got := agentWithNoIdentity(t).askTheWitnesses("EFresh", freshClaim(w))
	if got.Corroborated() || got.Behind != 1 || got.Held != 0 || got.Contradicted {
		t.Fatalf("a copy with no digest counted as held: %+v", got)
	}
}
