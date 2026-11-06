package recovery

import (
	"strings"
	"testing"

	"identity-agent-core/store"
)

// Fixed key material has a private half anyone can rebuild from its seed, so a
// root minted from it would belong to everyone. A break-glass rotation that
// asks for it is refused before anything is committed, rather than quietly
// given real keys.
func TestARootIsNeverMintedFromFixedMaterial(t *testing.T) {
	withRootAIDRotationEnabled(t, func() {
		st := &memNotifyStore{identity: &store.IdentityState{AID: "EoldRootAID0123456789ABCDEFGHIJKLMN"}}
		commits := 0
		commit := func([]byte, []string) error { commits++; return nil }
		for name, req := range map[string]RootAIDRotationRequest{
			"fixed material":       {RecoverySessionID: "sess-1", UseHybridInception: true, HybridSynthetic: true},
			"a root of the core's": {RecoverySessionID: "sess-1", UseHybridInception: true},
		} {
			_, err := RotateRootAID(req, commit, st, t.TempDir(), nil)
			if err == nil || !strings.Contains(err.Error(), "hybrid") {
				t.Fatalf("%s: not refused for it: %v", name, err)
			}
		}
		if commits != 0 {
			t.Fatalf("%d event(s) were committed before the refusal", commits)
		}
	})
}
