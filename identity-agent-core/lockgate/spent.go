package lockgate

import (
	"encoding/json"
	"os"
	"time"

	"identity-agent-core/atomicfile"
)

const spentFile = "spent-nonces.json"

type spentNonce struct {
	Nonce string    `json:"n"`
	At    time.Time `json:"at"`
}

// spendNonce records a log-in result's nonce as used, durably. It returns false
// when the nonce was already spent, or when the record cannot be written or is
// unreadable (fail closed). The caller serialises calls.
func (p *Profile) spendNonce(nonce string, now time.Time) bool {
	var all []spentNonce
	if b, err := os.ReadFile(p.path(spentFile)); err == nil {
		if json.Unmarshal(b, &all) != nil {
			return false
		}
	} else if !os.IsNotExist(err) {
		return false
	}
	kept := all[:0]
	for _, e := range all {
		if e.Nonce == nonce {
			return false
		}
		if now.Sub(e.At) < nonceMemory {
			kept = append(kept, e)
		}
	}
	if len(kept) >= nonceCap {
		kept = kept[len(kept)-nonceCap+1:]
	}
	kept = append(kept, spentNonce{Nonce: nonce, At: now})
	b, _ := json.Marshal(kept)
	return atomicfile.Write(p.path(spentFile), b, 0o600) == nil
}
