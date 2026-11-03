package messagingkeys

import (
	"encoding/json"

	"identity-agent-core/iacrypto"
)

// SealsAmong are the IA-HYBRID-1 keyset anchors among an event's seals, as the
// event carries them: the one reading of which seal commits to messaging keys.
func SealsAmong(seals []json.RawMessage) []json.RawMessage {
	var out []json.RawMessage
	for _, a := range seals {
		var probe struct {
			IA string `json:"ia"`
		}
		if json.Unmarshal(a, &probe) == nil && probe.IA == iacrypto.CipherSuiteIAHybrid1 {
			out = append(out, a)
		}
	}
	return out
}
