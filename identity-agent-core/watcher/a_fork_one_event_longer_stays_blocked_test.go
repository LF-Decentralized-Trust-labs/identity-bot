package watcher

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"identity-agent-core/store"
)

const deadWatcherURL = "http://127.0.0.1:1/public/kel-digest"

// aBlockedForkAt3Events sets up the case a retry must not get through: the
// standing watcher holds a different digest at position 2, so a 3-event log is
// blocked and an alert is kept.
func aBlockedForkAt3Events(t *testing.T) (ws *Service, aid, url string, try func(n int) *VerifyKelResult) {
	t.Helper()
	trusted := newTestWatcherKey(1)
	aid = "EHonest000000000000000000000000000000000000"
	url, serving := servedBy(t, &trusted, nil)
	seen(t, serving, aid, 2, "ffff")
	ws, _ = migratedWatcher(t)
	ws.L2 = clientTrusting(trusted)
	if err := ws.Store.SetConfig("default_l2_url", url); err != nil {
		t.Fatal(err)
	}
	try = func(n int) *VerifyKelResult {
		res, err := ws.VerifyKel(context.Background(), VerifyKelInput{AID: aid, KEL: keyLog(aid, n), SourceType: SourceOOBI})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if !try(3).Blocked {
		t.Fatal("control: the 3-event log must be blocked the first time")
	}
	return ws, aid, url, try
}

// The same fork offered one event longer has a new tip nobody has seen, so
// matching the alert on the tip alone let it through.
func TestAForkOneEventLongerIsBlockedWhetherOrNotTheWatcherIsReachable(t *testing.T) {
	ws, _, _, try := aBlockedForkAt3Events(t)
	if res := try(4); !res.Blocked {
		t.Fatalf("one event longer, watcher reachable: got through (%s)", res.OverallOutcome)
	}
	if err := ws.Store.SetConfig("default_l2_url", deadWatcherURL); err != nil {
		t.Fatal(err)
	}
	if res := try(4); !res.Blocked {
		t.Fatalf("one event longer, watcher unreachable: got through (%s)", res.OverallOutcome)
	}
	if res := try(5); !res.Blocked {
		t.Fatal("two events longer, watcher unreachable: got through")
	}
	if res := try(3); !res.Blocked {
		t.Fatal("the same log, watcher unreachable: got through")
	}
}

// Only the standing watcher now saying match, at the alert's own sequence
// number, lets the longer log pass without the owner resolving.
func TestALongerLogPassesWhenTheStandingWatcherNowMatchesAtTheAlertedSequence(t *testing.T) {
	trusted := newTestWatcherKey(1)
	aid := "EHonest000000000000000000000000000000000000"
	url, serving := servedBy(t, &trusted, nil)
	seen(t, serving, aid, 2, "ffff")
	ws, _ := migratedWatcher(t)
	ws.L2 = clientTrusting(trusted)
	_ = ws.Store.SetConfig("default_l2_url", url)
	run := func(n int) *VerifyKelResult {
		res, err := ws.VerifyKel(context.Background(), VerifyKelInput{AID: aid, KEL: keyLog(aid, n), SourceType: SourceOOBI})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if !run(3).Blocked {
		t.Fatal("control: blocked first")
	}
	ours, err := witnessproto.KelDigestAtSeq(keyLog(aid, 3), 2)
	if err != nil {
		t.Fatal(err)
	}
	seen(t, serving, aid, 2, ours) // the watcher now holds the digest this log carries at position 2
	tip, _ := witnessproto.KelDigestAtSeq(keyLog(aid, 4), 3)
	seen(t, serving, aid, 3, tip) // and at the longer log's tip
	if res := run(4); res.Blocked {
		t.Fatalf("the watcher agrees at the alerted sequence, yet blocked: %s", res.Reason)
	}
}

// Each retry used to add another alert (the identity includes the second, and an
// unreachable retry has no digest from them), so resolving one left the log
// blocked by the rest.
func TestRetriesOfAForkAddNoAlertAndOneResolveFreesTheLog(t *testing.T) {
	ws, aid, _, try := aBlockedForkAt3Events(t)
	time.Sleep(2100 * time.Millisecond) // past the second the alert's identity includes
	if !try(3).Blocked || !try(4).Blocked {
		t.Fatal("a retry got through")
	}
	if err := ws.Store.SetConfig("default_l2_url", deadWatcherURL); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if !try(3).Blocked || !try(4).Blocked {
		t.Fatal("an unreachable retry got through")
	}
	alerts, _ := ws.DisclosableAlerts(aid)
	if len(alerts) != 1 {
		t.Fatalf("%d alerts after retries, want the one", len(alerts))
	}
	if err := ws.ResolveAlert(alerts[0].ID, "confirmed with them"); err != nil {
		t.Fatal(err)
	}
	if res := try(4); res.Blocked {
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
// with the standing watcher unreachable: it has no first sighting and cannot
// give the digest at the alert's sequence, so only the open alert holds it.
func TestAShorterForkIsBlockedWhileAnAlertIsOpenAndTheWatcherIsUnreachable(t *testing.T) {
	trusted := newTestWatcherKey(1)
	aid := "EHonest000000000000000000000000000000000000"
	url, serving := servedBy(t, &trusted, nil)
	seen(t, serving, aid, 1, "eeee")
	seen(t, serving, aid, 2, "ffff")
	ws, _ := migratedWatcher(t)
	ws.L2 = clientTrusting(trusted)
	_ = ws.Store.SetConfig("default_l2_url", url)
	run := func(n int) *VerifyKelResult {
		res, err := ws.VerifyKel(context.Background(), VerifyKelInput{AID: aid, KEL: keyLog(aid, n), SourceType: SourceOOBI})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if r := run(3); !r.Blocked || r.duplicityAlert == nil || r.duplicityAlert.SequenceNum != 2 {
		t.Fatalf("control: want blocked with an alert at seq 2, got %+v", r)
	}
	_ = ws.Store.SetConfig("default_l2_url", deadWatcherURL)
	if r := run(2); !r.Blocked {
		t.Fatalf("cut to seq 1, watcher unreachable: got through (%s)", r.OverallOutcome)
	}
	// Reachable again but disagreeing at the tip: still held.
	_ = ws.Store.SetConfig("default_l2_url", url)
	if r := run(2); !r.Blocked {
		t.Fatalf("cut to seq 1, watcher disagrees: got through (%s)", r.OverallOutcome)
	}
}

// With an open alert a log passes only when the standing watcher matches at the
// tip and at the alert's sequence when the log reaches it.
func TestWithAnOpenAlertBothTheTipAndTheAlertedSequenceMustMatch(t *testing.T) {
	trusted := newTestWatcherKey(1)
	aid := "EHonest000000000000000000000000000000000000"
	url, serving := servedBy(t, &trusted, nil)
	seen(t, serving, aid, 2, "ffff")
	ws, _ := migratedWatcher(t)
	ws.L2 = clientTrusting(trusted)
	_ = ws.Store.SetConfig("default_l2_url", url)
	run := func(n int) *VerifyKelResult {
		res, _ := ws.VerifyKel(context.Background(), VerifyKelInput{AID: aid, KEL: keyLog(aid, n), SourceType: SourceOOBI})
		return res
	}
	if !run(3).Blocked {
		t.Fatal("control")
	}
	tip4, _ := witnessproto.KelDigestAtSeq(keyLog(aid, 4), 3)
	seen(t, serving, aid, 3, tip4) // tip matches, alerted seq 2 still differs
	if r := run(4); !r.Blocked {
		t.Fatal("tip matched but the alerted sequence did not: got through")
	}
	at2, _ := witnessproto.KelDigestAtSeq(keyLog(aid, 4), 2)
	seen(t, serving, aid, 2, at2)
	if r := run(4); r.Blocked {
		t.Fatalf("both matched, yet blocked: %s", r.Reason)
	}
}

// recordDuplicity's reuse of an open alert is a backstop the retry path no
// longer reaches, so it is exercised directly.
func TestRecordDuplicityReusesTheOpenAlertForTheSameLog(t *testing.T) {
	ws, _ := aFreshService(t)
	id1, a1, err := ws.recordDuplicity("EA", 2, "a", "u", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	id2, a2, err := ws.recordDuplicity("EA", 2, "a", "u", nil, nil)
	if err != nil || id1 != id2 || a1.ID != a2.ID {
		t.Fatalf("a second alert was added: %d %d %v", id1, id2, err)
	}
	if all, _ := ws.Store.listDuplicityAlerts("EA"); len(all) != 1 {
		t.Fatalf("%d alerts", len(all))
	}
}

// An escalated check keeps its verdict, and a block outranks it.
func TestAnEscalatedCheckKeepsItsVerdict(t *testing.T) {
	r := &VerifyKelResult{AID: "EA", OK: true, OverallOutcome: "escalated"}
	if v := r.Check().Verdict; v != VerdictEscalated {
		t.Fatalf("verdict %q", v)
	}
	r.Blocked, r.OverallOutcome = true, "duplicity"
	if v := r.Check().Verdict; v != VerdictDuplicity {
		t.Fatalf("a block read as %q", v)
	}
}
