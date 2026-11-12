package watcher

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"identity-agent-core/drivers/signedlog"
)

// A recovery after a key theft: base, then the thief's interaction with the
// retired key, and the owner's recovery rotation at the same place.
func aRecoveryAfterATheft(t *testing.T) (base, stale, recovered *signedlog.Log) {
	t.Helper()
	base = signedlog.Incept(t, signedlog.NewKeys(t, 3)).Interact("one")
	return base, base.Fork().Interact("thief"), base.Fork().Rotate()
}

// Fix 1. Once this agent has kept the recovered log, the thief's retired branch
// is not accepted as the identity's key state: the kept log is handed back, so
// everything is verified against the recovered key, and nothing against the
// retired one.
func TestAKeptRecoveryIsGoneOnWithWhenTheRetiredBranchIsPresented(t *testing.T) {
	trusted := newTestWatcherKey(1)
	_, stale, recovered := aRecoveryAfterATheft(t)
	ws := serviceAsking(t, trusted, aWatcherHolding(t, &trusted, nil).URL)
	if r := verifying(t, ws, recovered); !r.OK || r.Latest != nil {
		t.Fatalf("control: the recovered log first: %+v", r)
	}
	r := verifying(t, ws, stale)
	if r.Blocked || !r.OK {
		t.Fatalf("a retired branch is not duplicity: blocked=%v %s", r.Blocked, r.Reason)
	}
	if r.Latest == nil || len(r.LatestKeys) != 1 || r.LatestKeys[0] != recovered.Key() {
		t.Fatalf("the key state to go on with is %v, want the recovered key %s (the retired one is %s)", r.LatestKeys, recovered.Key(), stale.Key())
	}
	if len(r.LatestRecords) != recovered.Len() || r.LatestSeq != recovered.Len()-1 {
		t.Fatalf("the log to go on with has %d records to place %d", len(r.LatestRecords), r.LatestSeq)
	}
}

// Fix 2. The thief signs an interaction with the retired key at the place the
// recovery rotation holds; a watcher that kept it as a rival does not make the
// recovered identity two histories, whichever side holds the rotation.
func TestAnInteractionTheRetiredKeySignedAtTheRecoveryPlaceIsNotAFork(t *testing.T) {
	trusted := newTestWatcherKey(1)
	_, stale, recovered := aRecoveryAfterATheft(t)
	rivalRec := recordsOf(stale)[2]
	for name, held := range map[string]*signedlog.Log{
		"the watcher is ahead of the recovered log":   recovered.Fork().Interact("later"),
		"the watcher holds exactly the recovered log": recovered,
	} {
		w := aWatcherHolding(t, &trusted, held)
		w.Rival = append(w.Rival, rivalRec)
		w.RivalFlag.Store(true)
		r := verifying(t, serviceAsking(t, trusted, w.URL), recovered)
		if r.Blocked || !r.OK || len(r.FlaggedWatchers) != 0 {
			t.Errorf("%s: blocked=%v flagged=%v %s", name, r.Blocked, r.FlaggedWatchers, r.Reason)
		}
	}
	// And the other way: a retired interaction is a fork only where nothing
	// retires it (the same place, no recovery), which still refuses.
	honest, rival := twoHistories(t)
	w := aWatcherHolding(t, &trusted, honest)
	w.Rival = []map[string]interface{}{recordsOf(rival)[2]}
	w.RivalFlag.Store(true)
	if r := verifying(t, serviceAsking(t, trusted, w.URL), honest); !r.Blocked {
		t.Fatalf("two validly signed interactions at one place must still refuse: %+v", r)
	}
}

// Fix 3. An alert's evidence checks out from what it stores alone.
func TestAnAlertsEvidenceVerifiesFromWhatItStoresAlone(t *testing.T) {
	f := newBlockedFork(t)
	alerts, err := f.ws.Store.listDuplicityAlerts(f.honest.AID)
	if err != nil || len(alerts) == 0 {
		t.Fatalf("alerts: %v %v", alerts, err)
	}
	var ev Evidence
	if err := json.Unmarshal([]byte(alerts[0].Evidence), &ev); err != nil {
		t.Fatal(err)
	}
	if len(ev.PriorMessages) != ev.SequenceNum {
		t.Fatalf("the evidence holds %d prior events for place %d", len(ev.PriorMessages), ev.SequenceNum)
	}
	if err := ev.Reverify(); err != nil {
		t.Fatalf("the stored evidence does not re-verify: %v", err)
	}
	// Without the prefix it cannot, and an altered one does not.
	bare := ev
	bare.PriorMessages = nil
	if bare.Reverify() == nil {
		t.Error("evidence with no prior log re-verified")
	}
	same := ev
	same.RivalMessage = ev.HeldMessage
	if same.Reverify() == nil {
		t.Error("two copies of one event were taken as a fork")
	}
	swapped := ev
	swapped.PriorMessages = append([]string(nil), ev.PriorMessages...)
	swapped.PriorMessages[1] = base64.StdEncoding.EncodeToString([]byte("not an event"))
	if swapped.Reverify() == nil {
		t.Error("evidence over a damaged prior log re-verified")
	}
}

// Fix 4a. A rival that does not verify is a watcher lying, not a fork: the
// watcher is flagged and the contact is not refused. (Fails when the rival's
// signature is no longer checked.)
func TestAForgedRivalFlagsTheWatcherAndRefusesNobody(t *testing.T) {
	trusted := newTestWatcherKey(1)
	honest, rival := twoHistories(t)
	forged := recordsOf(rival)[2]
	forged["cesr_signature"] = honest.Records()[1]["cesr_signature"]
	w := aWatcherHolding(t, &trusted, honest)
	w.Rival = []map[string]interface{}{forged}
	w.RivalFlag.Store(true)
	r := verifying(t, serviceAsking(t, trusted, w.URL), honest)
	if r.Blocked || !r.OK || len(r.FlaggedWatchers) != 1 {
		t.Fatalf("blocked=%v ok=%v flagged=%v", r.Blocked, r.OK, r.FlaggedWatchers)
	}
}

// Fix 4b. A fork carried only in the rival list, which is how the hosted watcher
// hands one over, refuses. (Fails when rivals are never examined.)
func TestAForkCarriedOnlyInTheRivalListRefuses(t *testing.T) {
	trusted := newTestWatcherKey(1)
	honest, rival := twoHistories(t)
	w := aWatcherHolding(t, &trusted, honest)
	w.Rival = []map[string]interface{}{recordsOf(rival)[2]}
	w.RivalFlag.Store(true)
	r := verifying(t, serviceAsking(t, trusted, w.URL), honest)
	if !r.Blocked || r.OverallOutcome != VerdictDuplicity {
		t.Fatalf("blocked=%v outcome=%s", r.Blocked, r.OverallOutcome)
	}
}

// Fix 5. One invalid rival does not hide a valid one behind it: the valid one
// is acted on, and the watcher is flagged for the other.
func TestAnInvalidRivalDoesNotHideAValidOneBehindIt(t *testing.T) {
	trusted := newTestWatcherKey(1)
	honest, rival := twoHistories(t)
	bad := recordsOf(rival)[2]
	bad["cesr_signature"] = honest.Records()[1]["cesr_signature"]
	w := aWatcherHolding(t, &trusted, honest)
	w.Rival = []map[string]interface{}{bad, recordsOf(rival)[2]}
	w.RivalFlag.Store(true)
	r := verifying(t, serviceAsking(t, trusted, w.URL), honest)
	if !r.Blocked {
		t.Fatalf("a valid rival behind an invalid one was never examined: %+v", r)
	}
	if len(r.FlaggedWatchers) != 1 {
		t.Fatalf("the watcher was not flagged for the invalid rival: %v", r.FlaggedWatchers)
	}
}

// Item 9. A watcher whose digest matches the presented log but which holds a
// rival says so in its signed answer, and is then asked for its log; one that
// does not say so is not asked.
func TestAMatchingWatcherThatSaysItHoldsARivalIsAskedForItsLog(t *testing.T) {
	trusted := newTestWatcherKey(1)
	honest, rival := twoHistories(t)
	quiet := aWatcherHolding(t, &trusted, honest)
	quiet.Rival = []map[string]interface{}{recordsOf(rival)[2]}
	if r := verifying(t, serviceAsking(t, trusted, quiet.URL), honest); r.Blocked || quiet.LogFetches.Load() != 0 {
		t.Fatalf("control: with no flag its log is not asked for (fetches %d, blocked %v)", quiet.LogFetches.Load(), r.Blocked)
	}
	loud := aWatcherHolding(t, &trusted, honest)
	loud.Rival = []map[string]interface{}{recordsOf(rival)[2]}
	loud.RivalFlag.Store(true)
	r := verifying(t, serviceAsking(t, trusted, loud.URL), honest)
	if loud.LogFetches.Load() == 0 || !r.Blocked {
		t.Fatalf("flagged: fetches %d, blocked %v", loud.LogFetches.Load(), r.Blocked)
	}
}

// The flag is signed: one added on the way is not believed.
func TestARivalFlagAddedOnTheWayIsNotBelieved(t *testing.T) {
	trusted := newTestWatcherKey(1)
	honest, _ := twoHistories(t)
	c := clientTrusting(trusted)
	_, serving := servedBy(t, &trusted, nil)
	seen(t, serving, honest.AID, 0, "ab")
	resp, _ := serving.GetPublicDigest(honest.AID, 0)
	if err := c.verifyAnswer(resp, honest.AID, 0); err != nil {
		t.Fatalf("control: %v", err)
	}
	resp.RivalAtOrBelow = true // set after it was signed
	if err := c.verifyAnswer(resp, honest.AID, 0); err == nil {
		t.Fatal("an answer with the rival flag altered after signing was accepted")
	}
}

// Item 11. Two watchers that are each ahead of the presented log on different
// branches are compared with each other: two that conflict and both verify are
// proof of a fork, not a contest the longer branch wins.
func TestTwoAheadWatchersOnDifferentBranchesAreAForkNotALongestWins(t *testing.T) {
	trusted := newTestWatcherKey(1)
	base := signedlog.Incept(t, signedlog.NewKeys(t, 3)).Interact("one")
	presented := base
	a := base.Fork().Interact("a").Interact("a2")
	b := base.Fork().Interact("b").Interact("b2").Interact("b3") // longer
	wa, wb := aWatcherHolding(t, &trusted, a), aWatcherHolding(t, &trusted, b)
	ws := serviceAsking(t, trusted, wa.URL, wb.URL)
	r := verifying(t, ws, presented)
	if !r.Blocked || r.OverallOutcome != VerdictDuplicity || r.Latest != nil {
		t.Fatalf("blocked=%v outcome=%s latest=%d: the longer branch must not win", r.Blocked, r.OverallOutcome, len(r.Latest))
	}
	alerts, _ := ws.Store.listDuplicityAlerts(presented.AID)
	var ev Evidence
	if len(alerts) == 0 || json.Unmarshal([]byte(alerts[0].Evidence), &ev) != nil || ev.Reverify() != nil {
		t.Fatalf("the alert does not carry evidence that re-verifies: %+v", alerts)
	}
}

// Two ahead watchers where one holds a recovery of the other's branch are not a
// fork: the recovered branch is the one to go on with, however short.
func TestAnAheadWatcherHoldingTheRecoveryOutranksALongerRetiredBranch(t *testing.T) {
	trusted := newTestWatcherKey(1)
	base, stale, recovered := aRecoveryAfterATheft(t)
	longRetired := stale.Fork().Interact("t2").Interact("t3")
	for name, order := range map[string][2]*signedlog.Log{"retired first": {longRetired, recovered}, "recovered first": {recovered, longRetired}} {
		w1, w2 := aWatcherHolding(t, &trusted, order[0]), aWatcherHolding(t, &trusted, order[1])
		r := verifying(t, serviceAsking(t, trusted, w1.URL, w2.URL), base)
		if r.Blocked || len(r.LatestKeys) != 1 || r.LatestKeys[0] != recovered.Key() {
			t.Errorf("%s: blocked=%v keys=%v, want the recovered key %s", name, r.Blocked, r.LatestKeys, recovered.Key())
		}
	}
}

// Item 10. The first-seen signed log is kept, so a repeat contact whose log
// differs refuses on proof; and a first-seen row from before the log was kept
// (no signed log) never refuses on its digest alone.
func TestARepeatContactMismatchRefusesOnTheKeptSignedLogAndNeverOnABareDigest(t *testing.T) {
	trusted := newTestWatcherKey(1)
	honest, rival := twoHistories(t)
	silent := aWatcherHolding(t, &trusted, nil)

	ws := serviceAsking(t, trusted, silent.URL)
	if r := verifying(t, ws, honest); !r.OK {
		t.Fatalf("first contact: %+v", r)
	}
	if kept, err := ws.Store.getSeenLog(honest.AID); err != nil || len(kept) != honest.Len() {
		t.Fatalf("the first-seen signed log is not kept: %d events, %v", len(kept), err)
	}
	r := verifying(t, ws, rival)
	if !r.Blocked {
		t.Fatalf("a repeat contact whose log forks the kept one is not refused on proof: %+v", r)
	}

	// A row from before logs were kept: the digest is there, the signed log is
	// not. A different log is shown, never refused on the digest alone.
	old := serviceAsking(t, trusted, silent.URL)
	d := presenting(t, honest, SourceOOBI)
	seq := honest.Len() - 1
	digest, _ := witnessproto.KelDigestAtSeq(digestBasis(d), seq)
	seen(t, old, honest.AID, seq, digest)
	if _, err := old.Store.getSeenLog(honest.AID); err != nil {
		t.Fatal(err)
	}
	if err := old.Store.RecordFirstSeen(FirstSeenRecord{AID: honest.AID, SequenceNum: seq, KelDigest: digest,
		FirstSeenAt: old.now(), LastConfirmedAt: old.now(), SeenCount: 1, SourceType: SourceOOBI, Proven: true}); err != nil {
		t.Fatal(err)
	}
	rr := verifying(t, old, rival)
	if rr.Blocked {
		t.Fatalf("a bare digest from before logs were kept refused a contact: %s", rr.Reason)
	}
	if rr.OverallOutcome != "escalated" {
		t.Errorf("the difference is shown to the owner: outcome %s", rr.OverallOutcome)
	}
}
