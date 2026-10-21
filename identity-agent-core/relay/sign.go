package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// CanonicalBody is the exact bytes a control request is signed over
// (ADR-048 §8): its fields as a JSON object with sorted keys, no whitespace and
// no HTML escaping, with "signature" left out. It is the same form relayproto
// signs an admission statement in, so an implementation in any language
// produces the same bytes with an ordinary JSON writer.
//
// Every field is a string of printable ASCII, which is what makes the form
// unambiguous; anything else is refused rather than signed.
func CanonicalBody(body map[string]interface{}) ([]byte, error) {
	fields := make(map[string]string, len(body))
	for k, v := range body {
		if k == "signature" {
			continue
		}
		s, ok := v.(string)
		if !ok || !printableASCII(s) || !printableASCII(k) {
			return nil, fmt.Errorf("every field of a control request is a string of printable ASCII; %q is not", k)
		}
		fields[k] = s
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(fields); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
