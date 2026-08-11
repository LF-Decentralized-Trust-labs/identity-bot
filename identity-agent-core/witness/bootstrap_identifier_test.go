package witness

import (
	"strings"
	"testing"

	"identity-agent-core/iacrypto"
)

// A bootstrap witness is written into an identity's inception event, where it
// is public and permanent. If its identifier is not one a verifier can check a
// signature against, every receipt it ever issues is unverifiable — and by then
// the identifier cannot be changed, because it is part of identities that
// already exist.
//
// So this is checked here rather than discovered later: the pool previously
// carried identifiers prefixed to claim they were digests while actually being
// keys, which no KERI implementation could parse.
func TestEveryBootstrapWitnessIsNamedByACheckableKey(t *testing.T) {
	pool := BootstrapPool()
	if len(pool) == 0 {
		t.Fatal("there are no bootstrap witnesses, so a new identity has nobody to ask")
	}
	seen := map[string]string{}
	for _, w := range pool {
		if !strings.HasPrefix(w.AID, "B") || len(w.AID) != 44 {
			t.Errorf("%s is named %q, which is not a non-transferable identifier", w.URL, w.AID)
			continue
		}
		if _, err := iacrypto.KeyFromNonTransferableAID(w.AID); err != nil {
			t.Errorf("%s is named %q, which yields no key to check receipts against: %v",
				w.URL, w.AID, err)
		}
		// Two witnesses sharing an identifier would count as two independent
		// observers while being one, which inflates a threshold without adding
		// anybody.
		if prev, dup := seen[w.AID]; dup {
			t.Errorf("%s and %s share the identifier %s", prev, w.URL, w.AID)
		}
		seen[w.AID] = w.URL
		if w.URL == "" || w.Operator == "" {
			t.Errorf("witness %s has no address or no named operator", w.AID)
		}
	}
}

// A threshold above the number of independent operators can never be met.
func TestTheDefaultThresholdCanBeMetByTheBootstrapPool(t *testing.T) {
	if got := len(BootstrapPool()); MajorityThreshold(got) > got {
		t.Fatalf("a majority of %d witnesses is %d, which the pool cannot supply",
			got, MajorityThreshold(got))
	}
}
