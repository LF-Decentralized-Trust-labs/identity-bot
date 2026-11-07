package messagingkeys

import (
	"encoding/json"

	"identity-agent-core/iacrypto"
)

// SealsAmong are the IA-HYBRID-1 keyset anchors among an event's seals, as the
// event carries them. The decision is iacrypto.IsKeysetSeal's, not made again here.
func SealsAmong(seals []json.RawMessage) []json.RawMessage {
	return iacrypto.KeysetSealsAmong(seals)
}
