package server

import (
	"net/http"
	"time"

	"identity-agent-core/witness"
)

// Asking somebody other than the claimant whether this history is the whole
// history. The check itself is witness.Corroborate (one implementation, shared
// with verifiers outside the core); what stays here is only the choice of
// registry: the one this Identity Agent already uses to pick witnesses of its own.

// corroboration is what asking the witnesses established.
type corroboration = witness.Corroboration

// witnessKeysIn reads the witness keys an inception event designates.
var witnessKeysIn = witness.WitnessKeysIn

// askTheWitnesses checks a presented log against the parties it says were
// watching, each found by its designated key in this Identity Agent's registry.
func (s *CoreServer) askTheWitnesses(ownerAID string, presented []map[string]interface{}) corroboration {
	return witness.Corroborate(&http.Client{Timeout: 8 * time.Second}, witness.BootstrapPool(), ownerAID, presented)
}
