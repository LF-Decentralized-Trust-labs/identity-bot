package witness

import (
	"encoding/json"
	"fmt"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
)

func eventAID(ev map[string]interface{}) string {
	if v, ok := ev["i"].(string); ok {
		return v
	}
	return ""
}

// eventSeq is an event's sequence number, read by the rule every witness and
// watcher shares.
func eventSeq(ev map[string]interface{}) (int, error) {
	return witnessproto.SequenceNumber(ev)
}

// eventSAID is the identifier an event carries in its d field. An event with
// none is an error: an identifier made up from anything else (its length, say)
// is shared by every event of that length, so a receipt for one would pass for
// another. The digest cannot be recomputed from the parsed fields, only from
// the bytes the event was published as, so no identifier is better than a
// guessed one.
func eventSAID(ev map[string]interface{}) (string, error) {
	if v, ok := ev["d"].(string); ok && v != "" {
		return v, nil
	}
	return "", fmt.Errorf("the event carries no identifier (d), so it cannot be receipted")
}

func eventsToMaps(kel []KelEvent) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(kel))
	for _, e := range kel {
		var m map[string]interface{}
		if json.Unmarshal([]byte(e.EventJSON), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}
