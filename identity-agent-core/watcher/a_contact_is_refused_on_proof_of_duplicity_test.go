package watcher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers/signedlog"
)

func verifying(t *testing.T, ws *Service, l *signedlog.Log) *VerifyKelResult {
	t.Helper()
	res, err := ws.VerifyKel(context.Background(), presenting(t, l, SourceOOBI))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func serviceAsking(t *testing.T, trusted testWatcherKey, urls ...string) *Service {
	t.Helper()
	ws, _ := migratedWatcher(t)
	ws.L2 = clientTrusting(trusted)
	var more []string
	if len(urls) > 1 {
		more = urls[1:]
	}
	if err := setStanding(ws, urls[0], more...); err != nil {
		t.Fatal(err)
	}
	return ws
}

// A watcher cannot forge a controller signature, so it cannot forge a fork: a
// branch it makes up does not verify, its answer is set aside, the watcher is
// flagged, and the contact goes ahead, held for nothing.
func TestAForgedBranchFromALyingWatcherIsIgnoredAndTheWatcherFlagged(t *testing.T) {
	trusted := newTestWatcherKey(1)
	honest, rival := twoHistories(t)
	liar := aWatcherHolding(t, &trusted, rival)
	// The branch it shows has a signature that is not the controller's over that
	// event: it was copied from another event.
	liar.Alter = func(recs []map[string]interface{}) []map[string]interface{} {
		out := make([]map[string]interface{}, len(recs))
		for i, r := range recs {
			out[i] = map[string]interface{}{}
			for k, v := range r {
				out[i][k] = v
			}
		}
		out[2]["cesr_signature"] = honest.Records()[1]["cesr_signature"]
		return out
	}
	ws := serviceAsking(t, trusted, liar.URL)

	res := verifying(t, ws, honest)
	if res.Blocked || !res.OK {
		t.Fatalf("a branch that does not verify refused the contact: %+v", res)
	}
	if len(res.FlaggedWatchers) != 1 || res.FlaggedWatchers[0] != liar.URL {
		t.Fatalf("the watcher was not flagged: %v", res.FlaggedWatchers)
	}
	alerts, _ := ws.DisclosableAlerts(honest.AID)
	if len(alerts) != 1 || alerts[0].Kind != AlertKindWatcher || alerts[0].SourceURL != liar.URL || alerts[0].Evidence == "" {
		t.Fatalf("want one alert about the watcher: %+v", alerts)
	}
	if ws.openAlertFor(honest.AID, 2, res.Digest) {
		t.Fatal("an alert about a watcher blocks the contact")
	}
	// And the next contact is not held by it either.
	if again := verifying(t, ws, honest); again.Blocked {
		t.Fatalf("the flagged watcher blocked a repeat: %+v", again)
	}
	if c := res.Check(); c.Verdict != VerdictConfirmed || c.Sources[1].Outcome != OutcomeFaulty {
		t.Fatalf("check: %+v", c)
	}
}

// A watcher that holds exactly the presented events yet gives another digest has
// shown nothing against the contact. Nor is it flagged: the two sides may digest
// different renderings of the same events, so nothing proves the watcher at fault.
func TestAWatcherWhoseDigestDisagreesWithItsOwnLogIsShownNotFlagged(t *testing.T) {
	trusted := newTestWatcherKey(1)
	honest, rival := twoHistories(t)
	w := aWatcherHolding(t, &trusted, rival)
	w.Alter = func([]map[string]interface{}) []map[string]interface{} { return recordsOf(honest) }
	ws := serviceAsking(t, trusted, w.URL)
	if res := verifying(t, ws, honest); res.Blocked || len(res.FlaggedWatchers) != 0 || res.OverallOutcome != "escalated" {
		t.Fatalf("%+v", res)
	}
}

// One watcher's evidence is enough, and the alert keeps both events, each of
// which verifies on its own, so anybody can check the fork.
func TestARealValidlySignedForkFromOneWatcherRefuses(t *testing.T) {
	trusted := newTestWatcherKey(1)
	honest, rival := twoHistories(t)
	fork := aWatcherHolding(t, &trusted, rival)
	silent := aWatcherHolding(t, &trusted, nil) // has seen nothing: says nothing
	ws := serviceAsking(t, trusted, silent.URL, fork.URL)

	res := verifying(t, ws, honest)
	if !res.Blocked || res.OK {
		t.Fatalf("a proven fork did not refuse: %+v", res)
	}
	alerts, _ := ws.DisclosableAlerts(honest.AID)
	if len(alerts) != 1 || alerts[0].Kind != AlertKindDuplicity || alerts[0].SourceURL != fork.URL {
		t.Fatalf("alerts: %+v", alerts)
	}
	var ev Evidence
	if err := json.Unmarshal([]byte(alerts[0].Evidence), &ev); err != nil || ev.SequenceNum != 2 {
		t.Fatalf("evidence %q: %v", alerts[0].Evidence, err)
	}
	prior := honest.Cut(2)
	state, err := keri.ValidateSignedKEL(mustMessages(t, prior))
	if err != nil {
		t.Fatal(err)
	}
	for name, b64 := range map[string]string{"held": ev.HeldMessage, "rival": ev.RivalMessage} {
		m, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := keri.VerifyEvent(state.State(), m); err != nil {
			t.Fatalf("the %s event of the evidence does not verify: %v", name, err)
		}
	}
	if ev.HeldMessage == ev.RivalMessage {
		t.Fatal("the evidence holds one event twice")
	}
	// Each event says what it is, matching what keri-go reads from the message,
	// and names the key that signed it; the two differ in SAID, which is the fork.
	if len(ev.Events) != 2 || ev.Events[0].Role != "held" || ev.Events[1].Role != "rival" {
		t.Fatalf("the evidence does not describe both events: %+v", ev.Events)
	}
	for i, b64 := range []string{ev.HeldMessage, ev.RivalMessage} {
		m, _ := base64.StdEncoding.DecodeString(b64)
		parsed, err := keri.ParseEvent(m)
		if err != nil {
			t.Fatal(err)
		}
		d := ev.Events[i]
		if d.Type == "" || d.Type != parsed.Ilk || d.SAID == "" || d.SAID != parsed.SAID {
			t.Fatalf("event %d described as %+v, the message says %s %s", i, d, parsed.Ilk, parsed.SAID)
		}
		v, err := keri.VerifyEvent(state.State(), m)
		if err != nil {
			t.Fatal(err)
		}
		if len(d.SigningKeys) == 0 || d.SigningKeys[0] != v.State.Keys()[0] {
			t.Fatalf("event %d signing keys %v, want %v", i, d.SigningKeys, v.State.Keys())
		}
	}
	if ev.Events[0].SAID == ev.Events[1].SAID {
		t.Fatal("the two events share a SAID")
	}
	// An alert stored before the field existed is described when it is read back.
	old := ev
	old.Events = nil
	if got := old.withEvents(); len(got.Events) != 2 {
		t.Fatalf("a stored alert without the description was not described: %+v", got.Events)
	}
}

// The one place that cannot be proven here is a delegated rotation, which keri-go
// refuses without calling it duplicity; nothing here treats it as a fork. A
// disagreement that cannot be proven is shown and blocks nothing.
func TestADisagreementThatCannotBeProvenIsShownNotActedOn(t *testing.T) {
	trusted := newTestWatcherKey(1)
	honest, rival := twoHistories(t)
	w := aWatcherHolding(t, &trusted, rival)
	ws := serviceAsking(t, trusted, w.URL)

	// The watcher will not show its log: the same as no watcher.
	w.Hide.Store(true)
	res := verifying(t, ws, honest)
	if res.Blocked || !res.OK || res.OverallOutcome != "escalated" {
		t.Fatalf("a watcher that withholds its log: %+v", res)
	}
	// The presented log came without its signed bytes: nothing can be proven.
	w.Hide.Store(false)
	in := presenting(t, honest, SourceOOBI)
	in.Signed, in.NotSigned = nil, "event 0 carries no signed bytes"
	ws2 := serviceAsking(t, trusted, w.URL)
	got, err := ws2.VerifyKel(context.Background(), in)
	if err != nil || got.Blocked || got.OverallOutcome != "escalated" {
		t.Fatalf("parsed records only: %+v %v", got, err)
	}
	if w.LogFetches.Load() != 1 {
		t.Fatalf("the log was asked for %d times; parsed-only input must not fetch", w.LogFetches.Load())
	}
}

func mustMessages(t *testing.T, l *signedlog.Log) [][]byte {
	t.Helper()
	m, err := presenting(t, l, SourceOOBI).Signed, error(nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A recovery rotation replaces the interactions after the last establishment
// event, so two signed events at one place are not automatically a fork.
func TestASupersedingRecoveryRotationIsNotDuplicity(t *testing.T) {
	trusted := newTestWatcherKey(1)
	base := signedlog.Incept(t, signedlog.NewKeys(t, 3))
	stale := base.Fork().Interact("retired") // icp, ixn
	recovered := base.Fork().Rotate()        // icp, rot at the place the ixn holds

	// The presented log holds the retired interaction; the watcher has the
	// recovery: the presenter is stale, nothing is duplicitous, and the later
	// state is handed on.
	w := aWatcherHolding(t, &trusted, recovered)
	ws := serviceAsking(t, trusted, w.URL)
	res := verifying(t, ws, stale)
	if res.Blocked || !res.OK {
		t.Fatalf("a recovery rotation was called duplicity: %+v", res)
	}
	if len(res.Latest) != 2 || len(res.LatestRecords) != 2 || res.LatestKeys[0] != recovered.Key() {
		t.Fatalf("the recovered key state was not adopted: latest=%d keys=%v", len(res.Latest), res.LatestKeys)
	}

	// The presented log carries the recovery; the watcher still holds the retired
	// interaction: the watcher is behind, not wrong, and is not flagged.
	w2 := aWatcherHolding(t, &trusted, stale)
	ws2 := serviceAsking(t, trusted, w2.URL)
	res2 := verifying(t, ws2, recovered)
	if res2.Blocked || !res2.OK || len(res2.FlaggedWatchers) != 0 || res2.Latest != nil {
		t.Fatalf("a watcher behind a recovery: %+v", res2)
	}
	if c := res2.Check(); c.Sources[1].Outcome != OutcomeBehind {
		t.Fatalf("check: %+v", c)
	}
}

// A watcher holding validly signed later events shows the presenter's key state
// stale: the key it ends on may have been retired by a rotation, so the latest
// state is adopted, from evidence checked here.
func TestAWatcherAheadOfThePresentedLogUpdatesTheKeyState(t *testing.T) {
	trusted := newTestWatcherKey(1)
	short := signedlog.Incept(t, signedlog.NewKeys(t, 3)).Interact("one")
	longer := short.Fork().Rotate().Interact("two")
	w := aWatcherHolding(t, &trusted, longer)
	ws := serviceAsking(t, trusted, w.URL)

	res := verifying(t, ws, short)
	if res.Blocked || !res.OK {
		t.Fatalf("a watcher ahead blocked: %+v", res)
	}
	if len(res.Latest) != 4 || res.LatestSeq != 3 || len(res.LatestRecords) != 4 {
		t.Fatalf("latest: %d messages, seq %d", len(res.Latest), res.LatestSeq)
	}
	if len(res.LatestKeys) != 1 || res.LatestKeys[0] != longer.Key() || res.LatestKeys[0] == short.Key() {
		t.Fatalf("the key now in force is %v, want the rotated %s (not %s)", res.LatestKeys, longer.Key(), short.Key())
	}
	if c := res.Check(); c.Sources[1].Outcome != OutcomeAhead {
		t.Fatalf("check: %+v", c)
	}
	// What is adopted verifies on its own.
	if _, err := keri.ValidateSignedKEL(res.Latest); err != nil {
		t.Fatalf("the adopted log does not verify: %v", err)
	}
}

// Several standing watchers are for coverage: any one that shows the fork is
// enough, whatever the rest say, and none is counted.
func TestAnyOneStandingWatcherShowingAForkIsEnough(t *testing.T) {
	trusted := newTestWatcherKey(1)
	honest, rival := twoHistories(t)
	agree := aWatcherHolding(t, &trusted, honest)
	fork := aWatcherHolding(t, &trusted, rival)
	ws := serviceAsking(t, trusted, agree.URL, fork.URL)
	if res := verifying(t, ws, honest); !res.Blocked {
		t.Fatalf("one of two watchers proved the fork, yet: %+v", res)
	}
	// And with only watchers that agree, nothing is asked of any log.
	ws2 := serviceAsking(t, trusted, agree.URL)
	if res := verifying(t, ws2, honest); res.Blocked || agree.LogFetches.Load() != 0 {
		t.Fatalf("agreeing watcher: %+v fetches=%d", res, agree.LogFetches.Load())
	}
}

// An organisation is advised several standing watchers for coverage; that is a
// recommendation about reach, and it never decides a refusal.
func TestAnOrganisationIsAdvisedAtLeastTwoStandingWatchers(t *testing.T) {
	ws, _ := migratedWatcher(t)
	if !ws.StandingPolicyMet() {
		t.Fatal("an individual has no minimum")
	}
	if err := ws.Store.SetConfig(configEntityKind, EntityOrganisation); err != nil {
		t.Fatal(err)
	}
	if ws.StandingPolicyMet() {
		t.Fatal("an organisation with one standing watcher meets the advice")
	}
	if err := ws.SetStandingWatchers([]StandingWatcher{{URL: "https://w2.example/x"}}); err != nil {
		t.Fatal(err)
	}
	if !ws.StandingPolicyMet() {
		t.Fatal("two standing watchers should meet it")
	}
}
