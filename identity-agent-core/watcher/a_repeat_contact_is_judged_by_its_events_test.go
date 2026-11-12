package watcher

import (
	"context"
	"encoding/json"
	"testing"

	"identity-agent-core/drivers/signedlog"
)

func sawLog(t *testing.T, ws *Service, l *signedlog.Log) *VerifyKelResult {
	t.Helper()
	return verifying(t, ws, l)
}

// The case a reviewer reproduced: somebody holding the current key signs an
// interaction at place 2 and this agent sees it first. The owner's own recovery
// rotation at place 2, signed by the key the log pre-committed to, is not
// duplicity and is not refused.
func TestARecoveryRotationIsNotRefusedByAnEarlierSignedInteraction(t *testing.T) {
	ws, _ := migratedWatcher(t)
	base := signedlog.Incept(t, signedlog.NewKeys(t, 3)).Interact("first")
	attacker := base.Fork().Interact("evil")
	owner := base.Fork().Rotate()

	if res := sawLog(t, ws, attacker); res.Blocked {
		t.Fatalf("the first sighting was refused: %+v", res)
	}
	res := sawLog(t, ws, owner)
	if res.Blocked || !res.OK {
		t.Fatalf("the owner's recovery rotation was refused: %+v", res)
	}
	if alerts, _ := ws.DisclosableAlerts(owner.AID); len(alerts) != 0 {
		t.Fatalf("an alert was raised against a recovery rotation: %+v", alerts)
	}

	// The rotation is now the log this agent holds: the owner's next event goes on
	// from it, and the retired branch shown again is not duplicity either.
	next := owner.Interact("after")
	if res := sawLog(t, ws, next); res.Blocked || !res.OK {
		t.Fatalf("the owner's log after the rotation was refused: %+v", res)
	}
	if res := sawLog(t, ws, attacker); res.Blocked {
		t.Fatalf("the branch the rotation retired was refused when shown again: %+v", res)
	}
	kept, err := ws.Store.getSeenLog(owner.AID)
	if err != nil || len(kept) != next.Len() {
		t.Fatalf("the kept log is not the owner's longest: %d messages, want %d (%v)", len(kept), next.Len(), err)
	}
}

// Two events at one place that no recovery explains are still duplicity, shown
// by both events, from this agent's own record and no watcher's word.
func TestTwoSignedEventsAtOnePlaceAreRefusedWithBothAsEvidence(t *testing.T) {
	ws, _ := migratedWatcher(t)
	honest, rival := twoHistories(t)
	if res := sawLog(t, ws, honest); res.Blocked {
		t.Fatalf("%+v", res)
	}
	res := sawLog(t, ws, rival)
	if !res.Blocked {
		t.Fatalf("a rival signed event at a held place was not refused: %+v", res)
	}
	alerts, err := ws.DisclosableAlerts(honest.AID)
	if err != nil || len(alerts) != 1 || alerts[0].Evidence == "" {
		t.Fatalf("want one alert with evidence: %+v %v", alerts, err)
	}
	var ev Evidence
	if err := json.Unmarshal([]byte(alerts[0].Evidence), &ev); err != nil || ev.HeldMessage == "" || ev.RivalMessage == "" || ev.HeldMessage == ev.RivalMessage {
		t.Fatalf("the alert does not hold both events: %+v %v", ev, err)
	}
}

// A fork lower in the log than the tip is caught too: the old check compared the
// digest at the tip only, so a longer log that forks earlier found no sighting.
func TestAForkBelowTheTipOfALongerLogIsRefused(t *testing.T) {
	ws, _ := migratedWatcher(t)
	base := signedlog.Incept(t, signedlog.NewKeys(t, 3)).Interact("first")
	honest := base.Fork().Interact("honest")
	rival := base.Fork().Interact("rival").Interact("longer")
	if res := sawLog(t, ws, honest); res.Blocked {
		t.Fatalf("%+v", res)
	}
	if res := sawLog(t, ws, rival); !res.Blocked {
		t.Fatalf("a longer log forking below its tip was not refused: %+v", res)
	}
}

// A log that only goes on from the kept one, or is an older part of it, is not
// duplicity.
func TestALongerAndAnOlderPartOfTheSameLogAreNotRefused(t *testing.T) {
	ws, _ := migratedWatcher(t)
	base := signedlog.Incept(t, signedlog.NewKeys(t, 3)).Interact("one")
	longer := base.Interact("two").Interact("three")
	for _, l := range []*signedlog.Log{base, longer, base, longer} {
		if res := sawLog(t, ws, l); res.Blocked || !res.OK {
			t.Fatalf("%d events refused: %+v", l.Len(), res)
		}
	}
}

// The kept log is bounded to what verified: a log that proves nothing is never
// kept, and a log with no kept log to judge by is shown, not refused on.
func TestAnUnprovenLogIsNeverKept(t *testing.T) {
	ws, _ := migratedWatcher(t)
	honest, _ := twoHistories(t)
	in := presenting(t, honest, SourceOOBI)
	in.Signed, in.NotSigned = nil, "records only"
	if _, err := ws.VerifyKel(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if kept, _ := ws.Store.getSeenLog(honest.AID); kept != nil {
		t.Fatalf("a log that proved nothing was kept: %d messages", len(kept))
	}
}
