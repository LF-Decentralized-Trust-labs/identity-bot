package server

import (
	"net/http"
	"testing"
)

// answerEmptyFor makes the stand-in answer an identifier it holds nothing for
// the way the production witnesses do: HTTP 200 {"count":0,"kel":null}.
func answerEmptyFor(w *standInWitness, aid string) {
	w.Config.Handler.(*http.ServeMux).HandleFunc("/witness/kel/"+aid, func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write([]byte(`{"count":0,"kel":null}`))
	})
}

// freshClaim is a claimant whose inception names the stand-in witness, and the
// claim it presents: that inception, signed by its own key.
func freshClaim(t *testing.T, w *standInWitness) (*rotatingController, []map[string]interface{}) {
	t.Helper()
	c := newRotatingControllerWitnessedBy(t, "fresh", w.key)
	return c, []map[string]interface{}{inceptionRecordOf(c)}
}

// A designated witness that answers 200 and holds nothing for the identifier
// confirms nothing.
func TestAWitnessAnsweringWithAnEmptyLogDoesNotCorroborate(t *testing.T) {
	w := newStandInWitness(t)
	c, claim := freshClaim(t, w)
	answerEmptyFor(w, c.aid)
	got := agentWithNoIdentity(t).askTheWitnesses(c.aid, claim)
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
	c, claim := freshClaim(t, w)
	w.held[c.aid] = []map[string]interface{}{}
	got := agentWithNoIdentity(t).askTheWitnesses(c.aid, claim)
	if got.Corroborated() || got.Empty != 1 {
		t.Fatalf("an empty log corroborated: %+v", got)
	}
}

// A witness holding the events, same digests, is counted held.
func TestAWitnessHoldingTheEventsIsCountedHeld(t *testing.T) {
	w := newStandInWitness(t)
	c, claim := freshClaim(t, w)
	w.held[c.aid] = claim
	got := agentWithNoIdentity(t).askTheWitnesses(c.aid, claim)
	// Held is the witness's side: a signed notice that this is its newest
	// event. Whether the log was receipted is the other, and is not in a stand-in.
	if got.Held != 1 || got.Empty != 0 || got.Contradicted {
		t.Fatalf("a witness holding the claimed history was not counted held: %+v", got)
	}
}

// Same place, a different event the identity signed: a fork, and a
// contradiction. The witness shows it; saying so would not be enough.
func TestAWitnessHoldingADifferentEventContradicts(t *testing.T) {
	w := newStandInWitness(t)
	c, icp := freshClaim(t, w)
	icpSAID := eventSAIDOf(t, icp[0])
	mine := signedInteractionAt(t, c, 1, icpSAID, "mine", c.signers[0])
	rival := signedInteractionAt(t, c, 1, icpSAID, "rival", c.signers[0])
	w.held[c.aid] = []map[string]interface{}{icp[0], rival}
	got := agentWithNoIdentity(t).askTheWitnesses(c.aid, []map[string]interface{}{icp[0], mine})
	if !got.Contradicted || got.Corroborated() {
		t.Fatalf("a different event at the same place was not a contradiction: %+v", got)
	}
}

// A rotation in the claimed log supersedes an interaction at its place, as in
// keripy, so a witness showing an interaction there, signed by the key the
// rotation replaced, is not a contradiction.
func TestAWitnessShowingAnInteractionTheClaimedRotationReplacedDoesNotContradict(t *testing.T) {
	w := newStandInWitness(t)
	c, icp := freshClaim(t, w)
	rot := signedRotation(t, c)
	rival := signedInteractionAt(t, c, 1, eventSAIDOf(t, icp[0]), "rival", c.signers[0])
	w.held[c.aid] = []map[string]interface{}{icp[0], rival}
	got := agentWithNoIdentity(t).askTheWitnesses(c.aid, []map[string]interface{}{icp[0], rot})
	if got.Contradicted || got.Corroborated() {
		t.Fatalf("an interaction the rotation replaced refused or corroborated the claim: %+v", got)
	}
}

// Some of the history, but less than claimed, does not corroborate it.
func TestAWitnessHoldingLessThanClaimedDoesNotCorroborate(t *testing.T) {
	w := newStandInWitness(t)
	c, icp := freshClaim(t, w)
	claim := append(icp, signedRotation(t, c))
	w.held[c.aid] = claim[:1]
	got := agentWithNoIdentity(t).askTheWitnesses(c.aid, claim)
	if got.Corroborated() || got.Behind != 1 || got.Contradicted {
		t.Fatalf("a witness behind the claim corroborated it: %+v", got)
	}
}

// A log whose verified bytes are one event cannot borrow the digest of another
// by carrying it as an unverified top-level "d" beside the bytes.
func TestATopLevelDigestBesideOtherBytesDoesNotCorroborate(t *testing.T) {
	w := newStandInWitness(t)
	c, claim := freshClaim(t, w)
	other, otherClaim := freshClaim(t, w) // another identity's inception the witness holds
	w.held[c.aid] = otherClaim
	claim[0]["d"] = eventSAIDOf(t, otherClaim[0]) // not covered by any verification
	_ = other
	got := agentWithNoIdentity(t).askTheWitnesses(c.aid, claim)
	if got.Corroborated() || got.Held != 0 {
		t.Fatalf("other bytes corroborated by forging a top-level d: %+v", got)
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

// A witness that cannot name the event it holds, only a copy with no digest,
// cannot sign a notice that says it, so it is not asked successfully and holds
// nothing.
func TestAWitnessThatCannotNameTheEventItHoldsIsNotHeld(t *testing.T) {
	w := newStandInWitness(t)
	c, claim := freshClaim(t, w)
	w.held[c.aid] = []map[string]interface{}{{"t": "icp", "i": c.aid, "s": "0", "b": []interface{}{w.key}}}
	got := agentWithNoIdentity(t).askTheWitnesses(c.aid, claim)
	if got.Corroborated() || got.Failed != 1 || got.Held != 0 || got.Contradicted {
		t.Fatalf("a copy with no digest counted as held: %+v", got)
	}
}
