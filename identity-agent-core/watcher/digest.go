package watcher

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"identity-agent-core/iacrypto"
)

// KelDigestAtSeq returns Blake3-256 CESR qb64 (code E) over the canonical serialized
// KEL through sequence seq (inclusive). Events are sorted by sequence number.
func KelDigestAtSeq(events []map[string]interface{}, seq int) (string, error) {
	filtered, err := eventsUpToSeq(events, seq)
	if err != nil {
		return "", err
	}
	raw, err := canonicalKELBytes(filtered)
	if err != nil {
		return "", err
	}
	return iacrypto.Blake3QB64(raw)
}

// CurrentSeq returns the highest sequence number present in KEL events.
func CurrentSeq(events []map[string]interface{}) int {
	max := -1
	for _, ev := range events {
		if s := eventSeq(ev); s > max {
			max = s
		}
	}
	return max
}

func eventsUpToSeq(events []map[string]interface{}, seq int) ([]map[string]interface{}, error) {
	out := make([]map[string]interface{}, 0, len(events))
	for _, ev := range events {
		if eventSeq(ev) <= seq {
			out = append(out, ev)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no KEL events at or before seq %d", seq)
	}
	sort.Slice(out, func(i, j int) bool {
		return eventSeq(out[i]) < eventSeq(out[j])
	})
	return out, nil
}

func eventSeq(ev map[string]interface{}) int {
	switch v := ev["s"].(type) {
	case string:
		n, _ := strconv.Atoi(v)
		return n
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	default:
		return -1
	}
}

// canonicalKELBytes serializes events as a compact JSON array (no insignificant whitespace).
func canonicalKELBytes(events []map[string]interface{}) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, ev := range events {
		if i > 0 {
			buf.WriteByte(',')
		}
		b, err := json.Marshal(ev)
		if err != nil {
			return nil, fmt.Errorf("marshal event %d: %w", i, err)
		}
		buf.Write(b)
	}
	buf.WriteByte(']')
	return buf.Bytes(), nil
}