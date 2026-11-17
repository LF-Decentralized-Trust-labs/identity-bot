package witness

import (
	"encoding/json"

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

// eventSAID is the event's own digest, as it states it in "d". An event that
// states none has no identifier: a SAID is a digest of the event and cannot be
// made up from anything else, and one made from the event's length would be
// shared by any two events that serialise to the same size. It is "" for such
// an event, and a caller that keys anything on it must refuse the event.
func eventSAID(ev map[string]interface{}) string {
	if v, ok := ev["d"].(string); ok {
		return v
	}
	return ""
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
