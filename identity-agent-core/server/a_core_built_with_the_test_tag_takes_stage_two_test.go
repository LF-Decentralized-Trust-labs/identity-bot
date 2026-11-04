//go:build kerigo_pqtest

package server

import (
	"encoding/base64"
	"net/http"
	"testing"

	"identity-agent-core/keymath"

	keri "github.com/grapeid/keri-go"
)

// pqSign is the app's ML-DSA-65 signature over raw, at the places it counts.
func pqSign(t *testing.T, seed, raw []byte, index, ondex int) string {
	t.Helper()
	sig, err := keymath.SignMLDSA65(seed, raw)
	if err != nil {
		t.Fatal(err)
	}
	q, err := keymath.EncodeMLDSA65IndexedSignature(sig, index, ondex)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func commit(t *testing.T, s *CoreServer, raw []byte, sigs ...string) (int, map[string]any) {
	t.Helper()
	return call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(raw), "sigs": sigs})
}

// A core built with the kerigo_pqtest tag takes the stage-two rotation of an
// identity founded at stage one, and then every interaction only with both
// signatures: the Ed25519 key alone is refused and writes nothing.
func TestACoreBuiltWithTheTestTagTakesStageTwo(t *testing.T) {
	if !keri.PostQuantumTestCodes() {
		t.Fatal("this build has no post-quantum test codes")
	}
	s, aid, k, pq, pqKeys := aStageOneIdentity(t)

	code, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", aStageTwoRotationRequest(t, aid, k, pqKeys))
	if code != http.StatusOK {
		t.Fatalf("prepare the stage-two rotation: %d %v", code, out)
	}
	rot := preparedBytes(t, out)
	// The Ed25519 key opens place 0 of the commitment, the post-quantum key place 1.
	if code, out := commit(t, s, rot, appSign(t, k[1], rot, true)); code == http.StatusCreated {
		t.Fatalf("a stage-two rotation signed by one of its two keys committed: %v", out)
	}
	code, out = commit(t, s, rot, appSign(t, k[1], rot, true), pqSign(t, pq[0], rot, 1, 1))
	if code != http.StatusCreated {
		t.Fatalf("commit the stage-two rotation: %d %v", code, out)
	}
	rotSAID := out["d"].(string)

	ixn := func() []byte {
		code, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{
			"aid": aid, "t": "ixn", "a": []map[string]string{{"d": "Etest"}},
			"after": map[string]string{"s": "1", "d": rotSAID}})
		if code != http.StatusOK {
			t.Fatalf("prepare the interaction: %d %v", code, out)
		}
		return preparedBytes(t, out)
	}()
	// Ed25519 alone is right and too few: the core does not add it. It holds it,
	// as it holds any event with several signers, for the other key to join.
	code, out = commit(t, s, ixn, appSign(t, k[1], ixn, false))
	if code != http.StatusAccepted || out["status"] != "waiting_for_signatures" {
		t.Fatalf("an interaction signed by the Ed25519 key alone: %d %v", code, out)
	}
	if own, _ := s.DataStore.GetIdentity(); own.EventCount != 2 {
		t.Fatalf("a refused interaction changed the log: %d events", own.EventCount)
	}
	code, out = commit(t, s, ixn, appSign(t, k[1], ixn, false), pqSign(t, pq[0], ixn, 1, 1))
	if code != http.StatusCreated {
		t.Fatalf("an interaction signed by both keys: %d %v", code, out)
	}
}

// A post-quantum signature counts only if it verifies: one made by another
// post-quantum key, at the right place, commits neither the stage-two rotation
// nor an interaction after it, and changes nothing.
func TestAForgedPostQuantumSignatureIsRefused(t *testing.T) {
	if !keri.PostQuantumTestCodes() {
		t.Fatal("this build has no post-quantum test codes")
	}
	s, aid, k, pq, pqKeys := aStageOneIdentity(t)
	code, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", aStageTwoRotationRequest(t, aid, k, pqKeys))
	if code != http.StatusOK {
		t.Fatalf("prepare the stage-two rotation: %d %v", code, out)
	}
	rot := preparedBytes(t, out)
	// pq[1] is not the key the rotation reveals.
	if code, out := commit(t, s, rot, appSign(t, k[1], rot, true), pqSign(t, pq[1], rot, 1, 1)); code == http.StatusCreated || code == http.StatusAccepted {
		t.Fatalf("a stage-two rotation with a forged post-quantum signature was taken: %d %v", code, out)
	}
	if own, _ := s.DataStore.GetIdentity(); own.EventCount != 1 {
		t.Fatalf("a refused rotation changed the log: %d events", own.EventCount)
	}

	code, out = commit(t, s, rot, appSign(t, k[1], rot, true), pqSign(t, pq[0], rot, 1, 1))
	if code != http.StatusCreated {
		t.Fatalf("commit the stage-two rotation: %d %v", code, out)
	}
	code, out = call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{
		"aid": aid, "t": "ixn", "a": []map[string]string{{"d": "Etest"}},
		"after": map[string]string{"s": "1", "d": out["d"].(string)}})
	if code != http.StatusOK {
		t.Fatalf("prepare the interaction: %d %v", code, out)
	}
	ixn := preparedBytes(t, out)
	if code, out := commit(t, s, ixn, appSign(t, k[1], ixn, false), pqSign(t, pq[1], ixn, 1, 1)); code == http.StatusCreated || code == http.StatusAccepted {
		t.Fatalf("an interaction with a forged post-quantum signature was taken: %d %v", code, out)
	}
	if own, _ := s.DataStore.GetIdentity(); own.EventCount != 2 {
		t.Fatalf("a refused interaction changed the log: %d events", own.EventCount)
	}
}
