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

func eventSAID(ev map[string]interface{}) string {
	if v, ok := ev["d"].(string); ok && v != "" {
		return v
	}
	b, _ := json.Marshal(ev)
	return fmt.Sprintf("EH%x", len(b))
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
