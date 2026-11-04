//go:build kerigo_pqtest

package server

import (
	"net/http"
	"testing"
)

// anInteractionAfterStageTwo prepares an interaction on the tip of a stage-two
// identity and signs it with both keys, returning the answer to its commit.
func anInteractionAfterStageTwo(t *testing.T, s *CoreServer, aid, after string, snAfter string, k, pq [][]byte) (int, map[string]any) {
	t.Helper()
	code, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{
		"aid": aid, "t": "ixn", "a": []map[string]string{{"d": "Etest" + snAfter}},
		"after": map[string]string{"s": snAfter, "d": after}})
	if code != http.StatusOK {
		t.Fatalf("prepare the interaction: %d %v", code, out)
	}
	ixn := preparedBytes(t, out)
	return commit(t, s, ixn, appSign(t, k[1], ixn, false), pqSign(t, pq[0], ixn, 1, 1))
}

// A stage-two identity keeps working after the core restarts: the post-quantum
// signatures it stored are read back as they were made, so the next dual-signed
// interaction commits instead of waiting for a signature that is already there.
func TestAStageTwoIdentityKeepsWorkingAfterARestart(t *testing.T) {
	s, aid, k, pq, pqKeys := aStageOneIdentity(t)
	_, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", aStageTwoRotationRequest(t, aid, k, pqKeys))
	rot := preparedBytes(t, out)
	code, out := commit(t, s, rot, appSign(t, k[1], rot, true), pqSign(t, pq[0], rot, 1, 1))
	if code != http.StatusCreated {
		t.Fatalf("commit the stage-two rotation: %d %v", code, out)
	}
	rotSAID := out["d"].(string)
	code, out = anInteractionAfterStageTwo(t, s, aid, rotSAID, "1", k, pq)
	if code != http.StatusCreated {
		t.Fatalf("the first dual-signed interaction: %d %v", code, out)
	}
	firstSAID := out["d"].(string)

	s.reloadIdentityIntoDriver()
	code, out = anInteractionAfterStageTwo(t, s, aid, firstSAID, "2", k, pq)
	if code != http.StatusCreated {
		t.Fatalf("a dual-signed interaction after a restart: %d %v", code, out)
	}
}

// An identity at stage two is restored from its verified log with the
// post-quantum signatures kept, and is then extended by a dual-signed event.
func TestAStageTwoIdentityIsRestoredFromItsVerifiedLog(t *testing.T) {
	s, aid, k, pq, pqKeys := aStageOneIdentity(t)
	_, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", aStageTwoRotationRequest(t, aid, k, pqKeys))
	rot := preparedBytes(t, out)
	code, out := commit(t, s, rot, appSign(t, k[1], rot, true), pqSign(t, pq[0], rot, 1, 1))
	if code != http.StatusCreated {
		t.Fatalf("commit the stage-two rotation: %d %v", code, out)
	}
	rotSAID := out["d"].(string)
	evs, _ := s.DataStore.GetEvents(aid)
	if len(evs) != 2 {
		t.Fatalf("%d events", len(evs))
	}
	var log []map[string]any
	for _, ev := range evs {
		log = append(log, map[string]any{"raw_b64": ev.RawBytesB64, "sigs": ev.ControllerSignatures()})
	}
	fresh := appHeldCore(t)
	if code, out := call(t, fresh, fresh.handleRestoreIdentity, "/api/identity/restore",
		map[string]any{"aid": aid, "events": log}); code != http.StatusCreated {
		t.Fatalf("restore a stage-two log: %d %v", code, out)
	}
	stored, _ := fresh.DataStore.GetEvents(aid)
	if got := len(stored[1].ControllerSignatures()); got != 2 {
		t.Fatalf("the restored rotation keeps %d of its 2 signatures", got)
	}
	code, out = anInteractionAfterStageTwo(t, fresh, aid, rotSAID, "1", k, pq)
	if code != http.StatusCreated {
		t.Fatalf("a dual-signed interaction on the restored identity: %d %v", code, out)
	}
}
