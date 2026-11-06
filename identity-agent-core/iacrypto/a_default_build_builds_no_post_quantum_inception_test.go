//go:build !kerigo_pqtest

package iacrypto_test

import (
	"errors"
	"testing"

	"identity-agent-core/iacrypto"
)

// A build that cannot read a post-quantum key (CESR has assigned no code for
// one, ADR-061) refuses to build an inception that names one, whether the
// identity stands alone or acts for a delegator, and builds nothing.
func TestADefaultBuildBuildsNoPostQuantumInception(t *testing.T) {
	m := iacrypto.SyntheticHybridKeyMaterial(1)
	if res, err := iacrypto.BuildHybridInception(m); !errors.Is(err, iacrypto.ErrNoPostQuantumCodes) || res != nil {
		t.Fatalf("a standalone hybrid inception: %v, %v", res, err)
	}
	if res, err := iacrypto.BuildHybridDelegatedInception(m, "EOWNER-AID"); !errors.Is(err, iacrypto.ErrNoPostQuantumCodes) || res != nil {
		t.Fatalf("a delegated hybrid inception: %v, %v", res, err)
	}
}
