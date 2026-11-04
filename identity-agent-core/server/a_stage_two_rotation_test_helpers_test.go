package server

import (
	"encoding/base64"
	"net/http"
	"testing"

	"identity-agent-core/keymath"
)

// aStageOneIdentity founds an identity the way the app does at stage one: the
// next-key commitment is [digest of the next Ed25519 key, digest of the next
// ML-DSA-65 key], nt "1". It returns the core, the identity, the Ed25519 seeds
// k[0..2] and the post-quantum seeds pq[0..1], and the founding's identifier.
func aStageOneIdentity(t *testing.T) (s *CoreServer, aid string, k [][]byte, pq [][]byte, pqKeys []keymath.PostQuantumNext) {
	t.Helper()
	s = appHeldCore(t)
	k = appSeeds(3)
	pq = [][]byte{append([]byte{0xB1}, make([]byte, 31)...), append([]byte{0xB2}, make([]byte, 31)...)}
	for _, seed := range pq {
		key, err := keymath.PostQuantumNextKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		pqKeys = append(pqKeys, *key)
	}
	code, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{
		"t": "icp", "k": []string{verkeyOf(k[0])}, "kt": "1",
		"n": []string{digestOfSeed(t, k[1]), pqKeys[0].Digest}, "nt": "1"})
	if code != http.StatusOK {
		t.Fatalf("prepare founding: %d %v", code, out)
	}
	icp := preparedBytes(t, out)
	code, out = call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(icp), "sigs": []string{appSign(t, k[0], icp, true)}})
	if code != http.StatusCreated {
		t.Fatalf("commit founding: %d %v", code, out)
	}
	own, _ := s.DataStore.GetIdentity()
	return s, own.AID, k, pq, pqKeys
}

// aStageTwoRotationRequest is the stage-two rotation: both revealed, both
// needed, both committed to again.
func aStageTwoRotationRequest(t *testing.T, aid string, k [][]byte, pqKeys []keymath.PostQuantumNext) map[string]any {
	t.Helper()
	return map[string]any{"aid": aid, "t": "rot",
		"k": []string{verkeyOf(k[1]), pqKeys[0].Verkey}, "kt": "2",
		"n": []string{digestOfSeed(t, k[2]), pqKeys[1].Digest}, "nt": "2",
		"after": map[string]string{"s": "0", "d": aid}}
}
