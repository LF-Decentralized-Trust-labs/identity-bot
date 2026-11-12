package watcher

import (
	"context"
	"testing"
)

// Anybody can show an agent a made-up log for an identity they do not control.
// The digest it leaves must not get the identity's real log refused later.
func TestADigestPlantedFromAMadeUpLogDoesNotRefuseTheRealLog(t *testing.T) {
	ws, _ := migratedWatcher(t)
	honest, _ := twoHistories(t)

	// A log for the victim's identifier that proves nothing: bare records.
	planted := presenting(t, honest, SourceOOBI)
	planted.Signed, planted.NotSigned = nil, "made up"
	planted.KEL = append([]map[string]interface{}(nil), planted.KEL...)
	planted.KEL[len(planted.KEL)-1] = map[string]interface{}{"t": "ixn", "i": honest.AID, "s": "2", "x": "planted"}
	res, err := ws.VerifyKel(context.Background(), planted)
	if err != nil || res.Blocked {
		t.Fatalf("planting: %+v %v", res, err)
	}

	real := verifying(t, ws, honest)
	if real.Blocked || !real.OK {
		t.Fatalf("the real log was refused for differing from a planted digest: %+v", real)
	}
	if kept, _ := ws.Store.getFirstSeen(honest.AID, 2); kept == nil || !kept.Proven || kept.KelDigest != real.Digest {
		t.Fatalf("the planted sighting was not replaced by the proven one: %+v", kept)
	}
}

// A second, unproven log never contradicts a proven first sighting into a refusal.
func TestAnUnprovenLogDoesNotContradictAProvenSighting(t *testing.T) {
	ws, _ := migratedWatcher(t)
	honest, _ := twoHistories(t)
	if res := verifying(t, ws, honest); res.Blocked {
		t.Fatalf("%+v", res)
	}
	other := presenting(t, honest, SourceOOBI)
	other.Signed, other.NotSigned = nil, "made up"
	other.KEL = append([]map[string]interface{}(nil), other.KEL...)
	other.KEL[len(other.KEL)-1] = map[string]interface{}{"t": "ixn", "i": honest.AID, "s": "2", "x": "other"}
	res, err := ws.VerifyKel(context.Background(), other)
	if err != nil || res.Blocked || res.OverallOutcome != "escalated" {
		t.Fatalf("%+v %v", res, err)
	}
}

// Two logs that each verify, with different digests at one place, still refuse:
// the agent saw both signed, so the fork is its own first-hand evidence.
func TestTwoProvenLogsThatDifferAtOnePlaceStillRefuse(t *testing.T) {
	ws, _ := migratedWatcher(t)
	honest, rival := twoHistories(t)
	if res := verifying(t, ws, honest); res.Blocked {
		t.Fatalf("%+v", res)
	}
	if res := verifying(t, ws, rival); !res.Blocked {
		t.Fatalf("a signed rival log was not refused: %+v", res)
	}
}
