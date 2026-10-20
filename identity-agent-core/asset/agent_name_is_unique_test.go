package asset

import (
	"errors"
	"testing"
)

// A second agent under a name already in use is refused before any key is
// derived or any identity is minted, however the name is spaced or cased.
func TestASecondAgentWithTheSameNameIsRefused(t *testing.T) {
	h, _ := newAgentForTest(t, []string{"infra.zone.list"})
	for _, name := range []string{"test-agent", " TEST-agent "} {
		_, err := h.ProvisionAgentAsset(name, []string{"infra.zone.list"}, nil, nil, nil)
		if !errors.Is(err, ErrAgentNameTaken) {
			t.Fatalf("provisioning %q again gave %v, want ErrAgentNameTaken", name, err)
		}
	}
}

// A different name gets past the name check to the real work — here the
// missing root identity, since this handler has none.
func TestADifferentNameIsNotRefusedAsTaken(t *testing.T) {
	h, _ := newAgentForTest(t, nil)
	_, err := h.ProvisionAgentAsset("another-agent", []string{"infra.zone.list"}, nil, nil, nil)
	if errors.Is(err, ErrAgentNameTaken) {
		t.Fatal("a name nobody uses was refused as taken")
	}
}
