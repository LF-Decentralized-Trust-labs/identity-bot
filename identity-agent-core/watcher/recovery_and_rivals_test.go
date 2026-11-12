package watcher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"identity-agent-core/drivers"
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

// The retired branch is not remembered. Once this agent has kept the recovered
// log, the thief presenting the retired branch does not change what is
// remembered as first seen at that place, so nothing built from it (the digest
// this agent answers with) names the branch recovery replaced.
//
// Fails when the stale path records the presented digest as first seen.
func TestAPresentedRetiredBranchDoesNotReplaceTheFirstSeenDigest(t *testing.T) {
	trusted := newTestWatcherKey(1)
	_, stale, recovered := aRecoveryAfterATheft(t)
	ws := serviceAsking(t, trusted, aWatcherHolding(t, &trusted, nil).URL)
	if r := verifying(t, ws, recovered); !r.OK {
		t.Fatalf("control: %+v", r)
	}
	seq := recovered.Len() - 1
	before, err := ws.Store.getFirstSeen(recovered.AID, seq)
	if err != nil || before == nil {
		t.Fatalf("the recovered log was not remembered: %v", err)
	}
	r := verifying(t, ws, stale)
	if r.Blocked || r.Latest == nil {
		t.Fatalf("control: the retired branch is met with the kept log: %+v", r)
	}
	if r.Digest == before.KelDigest {
		t.Fatal("control: the two branches digest alike, so this proves nothing")
	}
	after, err := ws.Store.getFirstSeen(recovered.AID, seq)
	if err != nil || after == nil {
		t.Fatalf("first seen: %v", err)
	}
	if after.KelDigest != before.KelDigest {
		t.Fatalf("the digest remembered at place %d is now the retired branch's (%s), was the recovered log's (%s)", seq, after.KelDigest, before.KelDigest)
	}
}

// A recovery is not a fork, however the pair is put to Reverify: the recovery
// rotation as the held event and the retired interaction as the rival, or the
// other way round. The same pair of events with no recovery between them is
// still a fork.
//
// Fails when Reverify does not apply recoveryRetires in both directions, or
// does not check the identifier.
func TestReverifyDoesNotAcceptARecoveryAsAFork(t *testing.T) {
	_, stale, recovered := aRecoveryAfterATheft(t)
	rec, err := drivers.SignedMessagesFromRecords(recovered.Records())
	if err != nil {
		t.Fatal(err)
	}
	ret, err := drivers.SignedMessagesFromRecords(stale.Records())
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(m []byte) string { return base64.StdEncoding.EncodeToString(m) }
	prior := []string{b64(rec[0]), b64(rec[1])}
	mk := func(held, rival []byte) Evidence {
		return Evidence{Kind: "duplicity", Identifier: recovered.AID, SequenceNum: 2,
			HeldMessage: b64(held), RivalMessage: b64(rival), PriorMessages: prior}
	}
	if err := mk(rec[2], ret[2]).Reverify(); err == nil {
		t.Error("a recovery rotation held, the retired interaction as the rival, was taken as a fork")
	}
	if err := mk(ret[2], rec[2]).Reverify(); err == nil {
		t.Error("the retired interaction held, the recovery rotation as the rival, was taken as a fork")
	}
	// Control: two interactions at one place are a fork, and the identifier is checked.
	honest, rival := twoHistories(t)
	hm, _ := drivers.SignedMessagesFromRecords(honest.Records())
	rm, _ := drivers.SignedMessagesFromRecords(rival.Records())
	fork := Evidence{Kind: "duplicity", Identifier: honest.AID, SequenceNum: 2,
		HeldMessage: b64(hm[2]), RivalMessage: b64(rm[2]), PriorMessages: []string{b64(hm[0]), b64(hm[1])}}
	if err := fork.Reverify(); err != nil {
		t.Fatalf("control: a real fork stopped re-verifying: %v", err)
	}
	other := fork
	other.Identifier = recovered.AID
	if other.Reverify() == nil {
		t.Error("evidence naming another identity re-verified")
	}
	none := fork
	none.Identifier = ""
	if none.Reverify() == nil {
		t.Error("evidence naming no identity re-verified")
	}
}

// When the key state in force is held only in a log that cannot be handed on as
// records, nothing is verified against the presented (possibly retired) one: the
// contact is stopped, and shown as unchecked, which is not a finding of
// duplicity. Here the kept recovered log has material after its signatures that
// keri-go reads and the record shape cannot carry.
//
// Fails when that case lets the retired branch through.
func TestAKeptLogThatCannotBeHandedOnStopsTheRetiredBranchAsUnchecked(t *testing.T) {
	trusted := newTestWatcherKey(1)
	_, stale, recovered := aRecoveryAfterATheft(t)
	ws := serviceAsking(t, trusted, aWatcherHolding(t, &trusted, nil).URL)
	if r := verifying(t, ws, recovered); !r.OK {
		t.Fatalf("control: %+v", r)
	}
	kept, err := drivers.SignedMessagesFromRecords(recovered.Records())
	if err != nil {
		t.Fatal(err)
	}
	kept[len(kept)-1] = append(append([]byte(nil), kept[len(kept)-1]...), "-BAA"...)
	if _, err := keri.ValidateSignedKEL(kept); err != nil {
		t.Fatalf("control: the log must still verify: %v", err)
	}
	if err := ws.Store.saveSeenLog(recovered.AID, kept, len(kept)-1, time.Now()); err != nil {
		t.Fatal(err)
	}
	r := verifying(t, ws, stale)
	if !r.Blocked || r.OK || r.OverallOutcome != "stale" {
		t.Fatalf("the retired branch was let through: blocked=%v ok=%v outcome=%s", r.Blocked, r.OK, r.OverallOutcome)
	}
	if r.Duplicity() || r.Check().Verdict != VerdictUnchecked {
		t.Fatalf("a log that could not be handed on is shown as %s", r.Check().Verdict)
	}
}

// A presented log counts as proven only if it verifies and is the identity it is
// presented as. One that does not is remembered but never founds a sighting that
// refuses a later log.
//
// Fails when the verification of the presented log is skipped.
func TestAPresentedLogThatDoesNotVerifyIsNotRememberedAsProven(t *testing.T) {
	trusted := newTestWatcherKey(1)
	honest, _ := twoHistories(t)
	ws := serviceAsking(t, trusted, aWatcherHolding(t, &trusted, nil).URL)

	forged := presenting(t, honest, SourceOOBI)
	bad := make([]map[string]interface{}, len(forged.KEL))
	for i, rec := range forged.KEL {
		c := map[string]interface{}{}
		for k, v := range rec {
			c[k] = v
		}
		bad[i] = c
	}
	// A signature that is well formed and wrong.
	zero, _ := keri.EncodeIndexedSignature(make([]byte, 64), keri.SignaturePlace{})
	bad[len(bad)-1]["cesr_signature"] = zero
	delete(bad[len(bad)-1], "cesr_signatures")
	forged.KEL = bad
	signed, err := drivers.SignedMessagesFromRecords(bad)
	if err != nil {
		t.Fatal(err)
	}
	forged.Signed = signed
	if _, err := ws.VerifyKel(context.Background(), forged); err != nil {
		t.Fatal(err)
	}
	fs, err := ws.Store.getFirstSeen(honest.AID, honest.Len()-1)
	if err != nil || fs == nil {
		t.Fatalf("first seen: %v", err)
	}
	if fs.Proven {
		t.Fatal("a log whose last signature is wrong was remembered as proven")
	}

	// The same log presented as another identity is not proven either.
	other := presenting(t, honest, SourceOOBI)
	other.AID = "ESomeoneElse"
	if _, err := ws.VerifyKel(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if fs, _ := ws.Store.getFirstSeen("ESomeoneElse", honest.Len()-1); fs != nil && fs.Proven {
		t.Fatal("a log presented as another identity was remembered as proven")
	}
}

// A watcher holding a recovery rotation where the presented log holds the
// thief's interaction is answered as having superseded it, and one holding
// only later events as ahead: the owner's screen and the log say which.
//
// Fails when the recovery case is reported as an ordinary later log.
func TestASupersedingWatcherIsNamedAsSuchAndALaterOneAsAhead(t *testing.T) {
	trusted := newTestWatcherKey(1)
	base, stale, recovered := aRecoveryAfterATheft(t)
	outcome := func(held, presented *signedlog.Log) string {
		t.Helper()
		ws := serviceAsking(t, trusted, aWatcherHolding(t, &trusted, held).URL)
		r := verifying(t, ws, presented)
		if r.Blocked || !r.OK {
			t.Fatalf("blocked=%v %s", r.Blocked, r.Reason)
		}
		for _, so := range r.sourcesQueried {
			if so.Type == "L2_standing" {
				return so.Outcome
			}
		}
		t.Fatalf("no standing source: %+v", r.sourcesQueried)
		return ""
	}
	if got := outcome(recovered, stale); got != "superseded" {
		t.Errorf("a watcher holding the recovery is reported as %q, want superseded", got)
	}
	if got := outcome(base.Fork().Interact("more"), base); got != "ahead" {
		t.Errorf("a watcher holding later events is reported as %q, want ahead", got)
	}
}

// A watcher that serves another identity's log under this identity's name is
// flagged as faulty, and the contact it said nothing true about goes ahead.
func TestAWatcherServingAnotherIdentitysLogIsFlagged(t *testing.T) {
	trusted := newTestWatcherKey(1)
	honest, rival := twoHistories(t)
	someoneElse := recordsOf(signedlog.Incept(t, signedlog.NewKeys(t, 3)).Interact("a").Interact("b"))
	// Its digests are those of a different branch of this identity, so it is asked
	// for its log, and the log it hands over is somebody else's.
	w := aWatcherHolding(t, &trusted, rival)
	w.Alter = func([]map[string]interface{}) []map[string]interface{} { return someoneElse }
	ws := serviceAsking(t, trusted, w.URL)
	r := verifying(t, ws, honest)
	if r.Blocked || !r.OK || len(r.FlaggedWatchers) == 0 {
		t.Fatalf("blocked=%v ok=%v flagged=%v %s", r.Blocked, r.OK, r.FlaggedWatchers, r.Reason)
	}
	// The alert says the watcher answered about someone else, which is not a
	// signature that failed: a screen words the two apart.
	alerts, _ := ws.Store.listDuplicityAlerts(presenting(t, honest, SourceOOBI).AID)
	found := false
	for _, a := range alerts {
		if a.Kind != AlertKindWatcher {
			continue
		}
		var ev Evidence
		if err := json.Unmarshal([]byte(a.Evidence), &ev); err != nil {
			t.Fatal(err)
		}
		found = true
		if !ev.WrongIdentity || ev.Why != "its log is for another identity" {
			t.Errorf("the flag is %+v, want a wrong-identity watcher", ev)
		}
	}
	if !found {
		t.Fatalf("no watcher alert was stored (%v)", r.FlaggedWatchers)
	}
}
