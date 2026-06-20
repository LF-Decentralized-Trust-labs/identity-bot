package witness

import (
	"encoding/json"
	"fmt"
	"strconv"
)

func eventAID(ev map[string]interface{}) string {
	if v, ok := ev["i"].(string); ok {
		return v
	}
	return ""
}

func eventSeq(ev map[string]interface{}) (int, error) {
	switch v := ev["s"].(type) {
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return -1, err
		}
		return n, nil
	case float64:
		return int(v), nil
	case int:
		return v, nil
	default:
		return -1, fmt.Errorf("missing sequence")
	}
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