package relay

import (
	"bytes"
	"encoding/json"
	"sort"
)

// CanonicalBody produces the deterministic byte encoding a request body is
// signed over: the JSON object with its "signature" field removed and its keys
// sorted. It is exported so a Signer implemented outside this package signs the
// exact bytes the operator verifies, rather than reimplementing the encoding and
// risking a drift that would make every signature silently unverifiable.
func CanonicalBody(v interface{}) ([]byte, error) {
	return canonicalBody(v)
}

func canonicalBody(v interface{}) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	delete(m, "signature")
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := json.Marshal(m[k])
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}
