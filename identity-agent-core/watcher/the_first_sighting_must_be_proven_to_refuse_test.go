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

// Real signed bytes with one parsed field edited must not found a sighting the
// real log then contradicts: the digest is of what the bytes are.
func TestARealSignedLogWithAnEditedFieldDoesNotPlantADigest(t *testing.T) {
	ws, _ := migratedWatcher(t)
	honest, _ := twoHistories(t)
	edited := presenting(t, honest, SourceOOBI)
	edited.KEL = append([]map[string]interface{}(nil), edited.KEL...)
	last := map[string]interface{}{}
	for k, v := range edited.KEL[len(edited.KEL)-1] {
		last[k] = v
	}
	last["x"] = "planted"
	edited.KEL[len(edited.KEL)-1] = last
	if res, err := ws.VerifyKel(context.Background(), edited); err != nil || res.Blocked {
		t.Fatalf("%+v %v", res, err)
	}
	if real := verifying(t, ws, honest); real.Blocked || !real.OK {
		t.Fatalf("the real log was refused for differing from a digest planted by an edited field: %+v", real)
	}
}

// One honest log shown in two record shapes is one log.
func TestOneHonestLogInTwoRecordShapesIsNotRefused(t *testing.T) {
	ws, _ := migratedWatcher(t)
	honest, _ := twoHistories(t)
	if res := verifying(t, ws, honest); res.Blocked {
		t.Fatalf("%+v", res)
	}
	slim := presenting(t, honest, SourceOOBI)
	slim.KEL = nil
	for _, rec := range honest.Records() {
		slim.KEL = append(slim.KEL, map[string]interface{}{
			"raw_bytes_b64": rec["raw_bytes_b64"], "cesr_signature": rec["cesr_signature"],
		})
	}
	// Placement reads the bytes, so records that only carry them still place.
	if res, err := ws.VerifyKel(context.Background(), slim); err != nil || res.Blocked || res.OverallOutcome == "escalated" {
		t.Fatalf("%+v %v", res, err)
	}
}

// A late write from a log that proved nothing never replaces a proven digest, so
// the order two checks happen to finish in cannot plant one.
func TestAnUnprovenWriteNeverOverwritesAProvenDigest(t *testing.T) {
	ws, _ := migratedWatcher(t)
	const aid = "ERace000000000000000000000000000000000000000"
	if err := ws.recordFirstSeen(aid, 2, "Ereal", SourceOOBI, "", true); err != nil {
		t.Fatal(err)
	}
	if err := ws.recordFirstSeen(aid, 2, "Eplanted", SourceOOBI, "", false); err != nil {
		t.Fatal(err)
	}
	if got, _ := ws.Store.getFirstSeen(aid, 2); got == nil || got.KelDigest != "Ereal" || !got.Proven {
		t.Fatalf("%+v", got)
	}
}

// A peer cross-check of a served log that verifies matches the digest the asker
// computes from the signed bytes, which is not the digest of the records.
func TestAPeerCheckMatchesTheDigestOfAProvenLog(t *testing.T) {
	honest, _ := twoHistories(t)
	in := presenting(t, honest, SourceOOBI)
	asker, _ := migratedWatcher(t)
	res, err := asker.VerifyKel(context.Background(), in)
	if err != nil || res.Digest == "" {
		t.Fatalf("%+v %v", res, err)
	}
	s, now := checkingService(t)
	served := func(aid string) ([]map[string]interface{}, bool) { return in.KEL, aid == honest.AID }
	resp, _, err := s.KelCheck(signedCheck(honest.AID, res.SequenceNum, res.Digest, now.Unix()), checkedAt, served)
	if err != nil || resp == nil || !resp.Match {
		t.Fatalf("an honest proven log's digest did not match its own served log: %+v %v", resp, err)
	}
}
