//go:build !kerigo_pqtest

package server

import (
	"net/http"
	"strings"
	"testing"

	"identity-agent-core/iacrypto"
)

// A build that cannot read a post-quantum key refuses to prepare a founding
// that names one, so the refusal comes before anyone signs, not at commit.
func TestADefaultBuildPreparesNoFoundingNamingAPostQuantumKey(t *testing.T) {
	s := appHeldCore(t)
	k := appSeeds(2)
	code, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{
		"t": "icp", "k": []string{verkeyOf(k[0]), iacrypto.CESRMLDSA65Verkey + strings.Repeat("A", 1923)},
		"kt": "2", "n": []string{digestOfSeed(t, k[1])}, "nt": "1"})
	if code == http.StatusOK {
		t.Fatalf("a default build prepared a founding naming a post-quantum key: %v", out)
	}
	if d, _ := out["details"].(string); !strings.Contains(d, iacrypto.ErrNoPostQuantumCodes.Error()) {
		t.Fatalf("refused for another reason: %v", out)
	}
}
