package recovery

import (
	"strings"
	"testing"

	"identity-agent-core/store"
)

type countingHybridDriver struct {
	mockKeriDriver
	hybridCalls int
}

func (d *countingHybridDriver) CreateHybridInception(name string) (*KeriInceptionResult, error) {
	d.hybridCalls++
	return d.mockKeriDriver.CreateHybridInception(name)
}

// Fixed key material has a private half anyone can rebuild from its seed, so a
// root minted from it would belong to everyone. A break-glass rotation that
// asks for it is refused before anything is minted, rather than quietly given
// real keys.
func TestARootIsNeverMintedFromFixedMaterial(t *testing.T) {
	withRootAIDRotationEnabled(t, func() {
		st := &memNotifyStore{identity: &store.IdentityState{AID: "EoldRootAID0123456789ABCDEFGHIJKLMN"}}
		driver := &countingHybridDriver{}
		_, err := RotateRootAID(RootAIDRotationRequest{
			RecoverySessionID:          "sess-1",
			PreRotationPublicKey:       "prerotpub",
			PreRotationNextPublicKey:   "prerotnext",
			AuthorizationCesrSignature: "0Bsig",
			UseHybridInception:         true,
			HybridSynthetic:            true,
		}, driver, st, t.TempDir(), nil)
		if err == nil || !strings.Contains(err.Error(), "hybrid_synthetic") {
			t.Fatalf("a rotation asking for fixed material was not refused for it: %v", err)
		}
		if driver.hybridCalls != 0 {
			t.Fatalf("a root was minted %d time(s) before the refusal", driver.hybridCalls)
		}
	})
}
