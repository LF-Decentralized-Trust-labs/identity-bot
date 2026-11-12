package watcher

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"identity-agent-core/drivers/signedlog"
	"identity-agent-core/store"
)

const deadWatcherURL = "http://127.0.0.1:1/public/kel-digest"

// twoHistories is one identity's key log taken two ways from its second event:
// honest and rival are each correctly signed by the one controller, three events
// long, and differ at place 2.
func twoHistories(t *testing.T) (honest, rival *signedlog.Log) {
	t.Helper()
	base := signedlog.Incept(t, signedlog.NewKeys(t, 3)).Interact("first")
	return base.Fork().Interact("honest"), base.Fork().Interact("rival")
}

// aBlockedFork is the case a retry must not get through: the standing watcher
// shows a validly signed rival event at place 2, so the 3-event honest log is
// blocked on proof and an alert is kept.
type aBlockedFork struct {
	ws      *Service
	honest  *signedlog.Log
	rival   *signedlog.Log
	trusted testWatcherKey
	url     string
}

func newBlockedFork(t *testing.T) *aBlockedFork {
	t.Helper()
	f := &aBlockedFork{trusted: newTestWatcherKey(1)}
	f.honest, f.rival = twoHistories(t)
	f.url = aWatcherHolding(t, &f.trusted, f.rival).URL
	f.ws, _ = migratedWatcher(t)
	f.ws.L2 = clientTrusting(f.trusted)
	if err := setStanding(f.ws, f.url); err != nil {
		t.Fatal(err)
	}
	if !f.try(t, 3).Blocked {
		t.Fatal("control: the 3-event log must be blocked the first time")
	}
	return f
}

// grown is the honest log carried on to n events (or cut back to n).
func (f *aBlockedFork) grown(n int) *signedlog.Log {
	l := f.honest.Fork()
	for l.Len() < n {
		l.Interact("more")
	}
	return l.Cut(n)
}

func (f *aBlockedFork) try(t *testing.T, n int) *VerifyKelResult {
	t.Helper()
	res, err := f.ws.VerifyKel(context.Background(), presenting(t, f.grown(n), SourceOOBI))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// The same fork offered one event longer has a new tip nobody has seen, so
// matching the alert on the tip alone let it through.
func TestAForkOneEventLongerIsBlockedWhetherOrNotTheWatcherIsReachable(t *testing.T) {
	f := newBlockedFork(t)
	if res := f.try(t, 4); !res.Blocked {
		t.Fatalf("one event longer, watcher reachable: got through (%s)", res.OverallOutcome)
	}
	if err := f.ws.Store.SetConfig("default_l2_url", deadWatcherURL); err != nil {
		t.Fatal(err)
	}
	if res := f.try(t, 4); !res.Blocked {
		t.Fatalf("one event longer, watcher unreachable: got through (%s)", res.OverallOutcome)
	}
	if res := f.try(t, 5); !res.Blocked {
		t.Fatal("two events longer, watcher unreachable: got through")
	}
	if res := f.try(t, 3); !res.Blocked {
		t.Fatal("the same log, watcher unreachable: got through")
	}
}

// The watcher now holding exactly the honest history, a longer honest log
// passes without the owner resolving: the open alert is about a history the
// watcher no longer shows.
func TestALongerLogPassesWhenTheStandingWatcherNowMatchesAtTheAlertedSequence(t *testing.T) {
	f := newBlockedFork(t)
	url := aWatcherHolding(t, &f.trusted, f.grown(4)).URL
	if err := setStanding(f.ws, url); err != nil {
		t.Fatal(err)
	}
	if res := f.try(t, 4); res.Blocked {
		t.Fatalf("the watcher agrees at the alerted sequence, yet blocked: %s", res.Reason)
	}
}

// Each retry used to add another alert (the identity includes the second, and an
// unreachable retry has no digest from them), so resolving one left the log
// blocked by the rest.
func TestRetriesOfAForkAddNoAlertAndOneResolveFreesTheLog(t *testing.T) {
	f := newBlockedFork(t)
	time.Sleep(2100 * time.Millisecond) // past the second the alert's identity includes
	if !f.try(t, 3).Blocked || !f.try(t, 4).Blocked {
		t.Fatal("a retry got through")
	}
	if err := f.ws.Store.SetConfig("default_l2_url", deadWatcherURL); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if !f.try(t, 3).Blocked || !f.try(t, 4).Blocked {
		t.Fatal("an unreachable retry got through")
	}
	alerts, _ := f.ws.DisclosableAlerts(f.honest.AID)
	if len(alerts) != 1 {
		t.Fatalf("%d alerts after retries, want the one", len(alerts))
	}
	if err := f.ws.ResolveAlert(alerts[0].ID, "confirmed with them"); err != nil {
		t.Fatal(err)
	}
	if res := f.try(t, 4); res.Blocked {
		t.Fatalf("resolved once, still blocked: %s", res.Reason)
	}
}

// An escalation is shown but never blocks, and does not hold a verdict.
func TestAnEscalationAlertNeverBlocksOrHoldsAVerdict(t *testing.T) {
	ws, _ := migratedWatcher(t)
	aid := "EEscalated0000000000000000000000000000000000"
	ours, _ := witnessproto.KelDigestAtSeq(keyLog(aid, 3), 2)
	if _, err := ws.Store.InsertDuplicityAlert(DuplicityAlert{
		AID: aid, SequenceNum: 2, OurDigest: ours, Kind: AlertKindEscalation, DetectedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if ws.openAlertFor(aid, 2, ours) {
		t.Fatal("an escalation counts as an open duplicity alert")
	}
	res, err := ws.VerifyKel(context.Background(), VerifyKelInput{AID: aid, KEL: keyLog(aid, 3), SourceType: SourceOOBI})
	if err != nil || res.Blocked {
		t.Fatalf("an escalation blocked: %+v %v", res, err)
	}
	_ = ws.RecordCheck(&VerifyKelResult{AID: aid, Blocked: true, OverallOutcome: "duplicity"})
	_ = ws.RecordCheck(&VerifyKelResult{AID: aid, OK: true, OverallOutcome: "confirmed"})
	if c, _ := ws.DisclosableCheck(aid); c == nil || c.Verdict != VerdictConfirmed {
		t.Fatalf("an open escalation held the verdict: %+v", c)
	}
}

// A row stored before kinds existed is a duplicity, and the migration can be run again.
func TestAnAlertWithNoKindIsADuplicityAndMigration55CanBeRunAgain(t *testing.T) {
	ws, db := aFreshService(t)
	if _, err := db.Exec(`INSERT INTO duplicity_alerts (aid, sequence_num, our_digest, their_digest, detected_at)
		VALUES ('EOld', 1, 'a', 'b', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := store.ReapplyIdentityMigration(db, 55); err != nil {
		t.Fatal(err)
	}
	if err := store.ReapplyIdentityMigration(db, 55); err != nil {
		t.Fatal(err)
	}
	alerts, _ := ws.Store.listDuplicityAlerts("EOld")
	if len(alerts) != 1 || alerts[0].Kind != AlertKindDuplicity || !ws.openAlertFor("EOld", 1, "a") {
		t.Fatalf("an old alert is not a blocking duplicity: %+v", alerts)
	}
}

// Two resolves cannot both succeed: the store itself refuses the second.
func TestTheStoreResolvesAnAlertOnlyOnce(t *testing.T) {
	ws, _ := aFreshService(t)
	id, _ := ws.Store.InsertDuplicityAlert(DuplicityAlert{AID: "EA", SequenceNum: 1, OurDigest: "a", TheirDigest: "b"})
	if err := ws.Store.ResolveAlert(id, "first", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := ws.Store.ResolveAlert(id, "second", time.Now()); !errors.Is(err, ErrAlertAlreadyResolved) {
		t.Fatalf("second resolve: %v", err)
	}
	if a, _ := ws.Store.getAlert(id); a.ResolutionNote != "first" {
		t.Fatalf("note overwritten: %q", a.ResolutionNote)
	}
}

// A fork that split before the tip it was first blocked at, offered on retry
// with the standing watcher unreachable: only the open alert holds it.
func TestAShorterForkIsBlockedWhileAnAlertIsOpenAndTheWatcherIsUnreachable(t *testing.T) {
	f := newBlockedFork(t)
	_ = f.ws.Store.SetConfig("default_l2_url", deadWatcherURL)
	if r := f.try(t, 2); !r.Blocked {
		t.Fatalf("cut to seq 1, watcher unreachable: got through (%s)", r.OverallOutcome)
	}
	// Reachable again and showing the rival: it is still the same fork.
	_ = setStanding(f.ws, f.url)
	if r := f.try(t, 2); !r.Blocked {
		t.Fatalf("cut to seq 1, watcher disagrees: got through (%s)", r.OverallOutcome)
	}
}

// With an open alert a log passes only when the standing watcher matches at the
// tip and at the alert's sequence when the log reaches it.
func TestWithAnOpenAlertBothTheTipAndTheAlertedSequenceMustMatch(t *testing.T) {
	f := newBlockedFork(t)
	// A watcher whose log matches the honest log at the tip but whose digest at the
	// alerted place still differs cannot be built from one log; the digest at 2
	// is the rival's here, and the tip is not held at all.
	if r := f.try(t, 4); !r.Blocked {
		t.Fatal("the alerted sequence still differs: got through")
	}
	url := aWatcherHolding(t, &f.trusted, f.grown(4)).URL
	_ = setStanding(f.ws, url)
	if r := f.try(t, 4); r.Blocked {
		t.Fatalf("both matched, yet blocked: %s", r.Reason)
	}
}
