package watcher

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/store"

	_ "modernc.org/sqlite"
)

// The own record's "had not seen this before" is the observation the opt-out
// hides, so a kept check says "agrees" for it, and never carries a digest.
func TestACheckFoldsWhatTheOptOutHidesAndKeepsWhatTheOwnerNeeds(t *testing.T) {
	r := &VerifyKelResult{
		AID: "EA", Digest: "Esecret", OK: true, OverallOutcome: "confirmed",
		sourcesQueried: []SourceOutcome{
			{Type: "L1", Outcome: "first_seen"},
			{Type: "L2_standing", URL: "https://w.example", Outcome: "unavailable"},
			{Type: "L2_bootstrap", URL: "https://h.example", Outcome: "unknown"},
			{Type: "L3", URL: "https://p.example", Outcome: "mismatch"},
		},
	}
	c := r.Check()
	got := ""
	for _, s := range c.Sources {
		got += s.Type + "=" + s.Outcome + " "
	}
	want := "own_record=agrees standing=unreachable hint=no_answer peer=disagrees "
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "Esecret") || strings.Contains(string(b), "first_seen") {
		t.Fatalf("a check carried an observation: %s", b)
	}
	if c.Verdict != VerdictConfirmed {
		t.Fatalf("verdict %q", c.Verdict)
	}
	if (&VerifyKelResult{AID: "EA", Blocked: true, OverallOutcome: "duplicity"}).Check().Verdict != VerdictDuplicity {
		t.Fatal("a blocked result must be a duplicity verdict")
	}
}

func TestOnlyTheNewestCheckOfAnIdentityIsKept(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.ApplyIdentityMigrations(db); err != nil {
		t.Fatal(err)
	}
	svc := NewService(NewSQLiteStore(db))
	for _, v := range []string{VerdictDuplicity, VerdictConfirmed} {
		res := &VerifyKelResult{AID: "EA", OverallOutcome: "confirmed"}
		res.Blocked = v == VerdictDuplicity
		if err := svc.RecordCheck(res); err != nil {
			t.Fatal(err)
		}
	}
	all, err := svc.DisclosableChecks()
	if err != nil || len(all) != 1 || all[0].Verdict != VerdictConfirmed {
		t.Fatalf("%v %+v", err, all)
	}
}

func aFreshService(t *testing.T) (*Service, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.ApplyIdentityMigrations(db); err != nil {
		t.Fatal(err)
	}
	return NewService(NewSQLiteStore(db)), db
}

// A later check that found nothing new must not hide a duplicity verdict whose
// alert is still open; once the owner resolves it, the newer check stands.
func TestADuplicityVerdictStandsWhileItsAlertIsOpen(t *testing.T) {
	svc, _ := aFreshService(t)
	if _, err := svc.Store.InsertDuplicityAlert(DuplicityAlert{AID: "EA", SequenceNum: 1, OurDigest: "a", TheirDigest: "b"}); err != nil {
		t.Fatal(err)
	}
	_ = svc.RecordCheck(&VerifyKelResult{AID: "EA", Blocked: true, OverallOutcome: "duplicity"})
	_ = svc.RecordCheck(&VerifyKelResult{AID: "EA", OK: true, OverallOutcome: "confirmed"})
	c, _ := svc.DisclosableCheck("EA")
	if c == nil || c.Verdict != VerdictDuplicity {
		t.Fatalf("an open alert was shown as confirmed: %+v", c)
	}
	alerts, _ := svc.DisclosableAlerts("EA")
	if err := svc.ResolveAlert(alerts[0].ID, "checked with them"); err != nil {
		t.Fatal(err)
	}
	_ = svc.RecordCheck(&VerifyKelResult{AID: "EA", OK: true, OverallOutcome: "confirmed"})
	if c, _ = svc.DisclosableCheck("EA"); c.Verdict != VerdictConfirmed {
		t.Fatalf("a resolved alert still holds the verdict: %+v", c)
	}
}

func TestMigration54CanBeRunAgain(t *testing.T) {
	_, db := aFreshService(t)
	if err := store.ReapplyIdentityMigration(db, 54); err != nil {
		t.Fatal(err)
	}
}

func TestAnOpenAlertAtASequenceKeepsBlockingUntilResolved(t *testing.T) {
	svc, _ := aFreshService(t)
	if svc.openAlertFor("EA", 1, "a") {
		t.Fatal("no alert yet")
	}
	id, _ := svc.Store.InsertDuplicityAlert(DuplicityAlert{AID: "EA", SequenceNum: 1, OurDigest: "a", TheirDigest: "b"})
	if !svc.openAlertFor("EA", 1, "a") || svc.openAlertFor("EA", 2, "a") {
		t.Fatal("an open alert must hold for its own sequence number only")
	}
	if svc.openAlertFor("EA", 1, "other") {
		t.Fatal("an alert holds for its own digest only")
	}
	if err := svc.ResolveAlert(id, "n"); err != nil {
		t.Fatal(err)
	}
	if err := svc.ResolveAlert(id, "second"); !errors.Is(err, ErrAlertAlreadyResolved) {
		t.Fatalf("a second resolve was accepted: %v", err)
	}
	if a, _ := svc.Store.getAlert(id); a.ResolutionNote != "n" {
		t.Fatalf("the audit note was overwritten: %q", a.ResolutionNote)
	}
	if svc.openAlertFor("EA", 1, "a") {
		t.Fatal("a resolved alert must not block")
	}
}

// The case the first-contact rule alone let through: the standing watcher
// disagrees, the first try is blocked, and the same log offered again must be
// blocked too. Only the owner resolving the alert lets it pass.
func TestTheSameForkedLogOfferedAgainIsStillBlockedUntilResolved(t *testing.T) {
	trusted := newTestWatcherKey(1)
	aid := "EHonest000000000000000000000000000000000000"
	url, serving := servedBy(t, &trusted, nil)
	seen(t, serving, aid, 2, "ffff")
	ws, _ := migratedWatcher(t)
	ws.L2 = clientTrusting(trusted)
	if err := ws.Store.SetConfig("default_l2_url", url); err != nil {
		t.Fatal(err)
	}
	try := func() *VerifyKelResult {
		res, err := ws.VerifyKel(context.Background(), VerifyKelInput{AID: aid, KEL: keyLog(aid, 3), SourceType: SourceOOBI})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if !try().Blocked {
		t.Fatal("control: the first try must be blocked")
	}
	if !try().Blocked {
		t.Fatal("a second try of the same log got through")
	}
	alerts, _ := ws.DisclosableAlerts(aid)
	if len(alerts) == 0 {
		t.Fatal("no alert kept")
	}
	for _, a := range alerts {
		if err := ws.ResolveAlert(a.ID, "confirmed with them in person"); err != nil {
			t.Fatal(err)
		}
	}
	if res := try(); res.Blocked {
		t.Fatalf("a resolved alert still blocks: %s", res.Reason)
	}
}

// The probe from review: the first try is blocked, the standing watcher then
// becomes unreachable, and the retry must not confirm the forked log.
func TestAForkedLogStaysBlockedOnARetryWhileTheStandingWatcherIsUnreachable(t *testing.T) {
	trusted := newTestWatcherKey(1)
	aid := "EHonest000000000000000000000000000000000000"
	url, serving := servedBy(t, &trusted, nil)
	seen(t, serving, aid, 2, "ffff")
	ws, _ := migratedWatcher(t)
	ws.L2 = clientTrusting(trusted)
	if err := ws.Store.SetConfig("default_l2_url", url); err != nil {
		t.Fatal(err)
	}
	try := func() *VerifyKelResult {
		res, err := ws.VerifyKel(context.Background(), VerifyKelInput{AID: aid, KEL: keyLog(aid, 3), SourceType: SourceOOBI})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if !try().Blocked {
		t.Fatal("control: the first try must be blocked")
	}
	if err := ws.Store.SetConfig("default_l2_url", "http://127.0.0.1:1/public/kel-digest"); err != nil {
		t.Fatal(err)
	}
	res := try()
	if !res.Blocked || res.OverallOutcome == "confirmed" {
		t.Fatalf("an unreachable standing watcher let a forked log through: blocked=%v outcome=%s", res.Blocked, res.OverallOutcome)
	}
	// The standing watcher's own entry reads unavailable: not agrees, not absent.
	if got := res.sourcesQueried; len(got) < 2 || got[1].Outcome != "unavailable" {
		t.Fatalf("the standing watcher should read unavailable: %+v", got)
	}
}

// An unreachable standing watcher and an unreachable hint are each reported as
// unreachable, never as agreeing and never as silence, in the check that is kept.
//
// Fails when the L2_standing "unavailable" source entry in VerifyKel is removed,
// or when a hint that cannot be reached stops reading "unavailable".
func TestUnreachableSourcesAreKeptAsUnreachable(t *testing.T) {
	ws, _ := migratedWatcher(t)
	aid := "EQuiet0000000000000000000000000000000000000"
	res, err := ws.VerifyKel(context.Background(), VerifyKelInput{
		AID: aid, KEL: keyLog(aid, 2), SourceType: SourceOOBI,
		BootstrapL2: []string{"http://127.0.0.1:2/public/kel-digest"},
	})
	if err != nil || !res.OK {
		t.Fatalf("an unreachable watcher alone must not block a first sighting: %v %+v", err, res)
	}
	got := map[string]string{}
	for _, c := range res.Check().Sources {
		got[c.Type] = c.Outcome
	}
	if got["standing"] != OutcomeUnreachable || got["hint"] != OutcomeUnreachable || got["own_record"] != OutcomeAgrees {
		t.Fatalf("sources: %v", got)
	}
}
