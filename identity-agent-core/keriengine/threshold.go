package keriengine

import (
	"encoding/json"
	"strings"

	keri "github.com/grapeid/keri-go"
)

// witnessThreshold reports how many witness receipts an event requires.
//
// An event that states no threshold is not an event requiring zero: the
// protocol derives a default from how many witnesses there are, and the two
// differ exactly when nobody asked. Reading the derived value off the parsed
// event rather than off the request is what keeps an identity from holding a
// threshold its own event does not agree with.
func witnessThreshold(ev *keri.Event) int {
	if ev == nil {
		return 0
	}
	if !ev.HasTOAD {
		return 0
	}
	return int(ev.TOAD)
}

// thresholdJSON renders a signing threshold in the form an event carries.
//
// A threshold is either a count, written as a hex string ("1", "2", "a"), or a
// weighted policy, written as a list of fractions (["1/2", "1/2", "1/3"]). The
// two are different JSON types, so a caller's string has to be routed to the
// right one — quoting a list would produce an event whose threshold is the
// literal text of a list and which no implementation can evaluate.
func thresholdJSON(s string) json.RawMessage {
	t := strings.TrimSpace(s)
	// Already JSON — a list, or a quoted string — so pass it through untouched.
	if strings.HasPrefix(t, "[") || strings.HasPrefix(t, "\"") {
		if json.Valid([]byte(t)) {
			return json.RawMessage(t)
		}
	}
	// A comma-separated set of weights is the other way callers spell a
	// weighted threshold.
	if strings.Contains(t, ",") {
		parts := strings.Split(t, ",")
		weights := make([]string, 0, len(parts))
		for _, p := range parts {
			weights = append(weights, strings.TrimSpace(p))
		}
		if b, err := json.Marshal(weights); err == nil {
			return b
		}
	}
	b, err := json.Marshal(t)
	if err != nil {
		return nil
	}
	return b
}
