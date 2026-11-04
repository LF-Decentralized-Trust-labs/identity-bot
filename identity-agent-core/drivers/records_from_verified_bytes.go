package drivers

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// RecordsFromVerifiedBytes rebuilds every record of a key log from its
// raw_bytes_b64, the one part of a record that a verdict from
// ValidateKELInputFromRecords covers (along with cesr_signature).
//
// A served record also carries the event as text (event_json), as parsed fields
// at the top level (t, k, ...), and a type and number. None of those is checked
// by the verdict, so a server could serve genuine bytes beside edited fields and
// the log would still read "verified". What comes back has every one of them
// derived from the bytes, replacing whatever was served, so a record kept as
// verified says only what was verified.
//
// ok is false when any record has no bytes, bytes that do not decode, or bytes
// that are not an event: such a log cannot have been verified by its bytes.
func RecordsFromVerifiedBytes(records []map[string]interface{}) ([]map[string]interface{}, bool) {
	if len(records) == 0 {
		return nil, false
	}
	out := make([]map[string]interface{}, 0, len(records))
	for _, rec := range records {
		// Decoded exactly as the verdict decodes them.
		rawB64, _ := rec["raw_bytes_b64"].(string)
		raw, err := DecodeRawBytes(rawB64)
		if err != nil || len(raw) == 0 {
			return nil, false
		}
		var ev map[string]interface{}
		if json.Unmarshal(raw, &ev) != nil || ev == nil {
			return nil, false
		}
		sig, _ := rec["cesr_signature"].(string)
		built := make(map[string]interface{}, len(ev)+5)
		for k, v := range ev {
			built[k] = v
		}
		built["event_json"] = string(raw)
		built["raw_bytes_b64"] = rawB64
		built["cesr_signature"] = sig
		if t, _ := ev["t"].(string); t != "" {
			built["event_type"] = t
		}
		if s, ok := ev["s"].(string); ok {
			if n, err := strconv.ParseInt(s, 16, 64); err == nil {
				built["sequence_number"] = n
			}
		}
		out = append(out, built)
	}
	return out, true
}

// SealedKEL is a stored contact log as it may be believed: when it is marked
// verified, every record is rebuilt from the verified bytes; when the bytes
// cannot be had, it is no longer marked verified, with the reason given.
func SealedKEL(kel []map[string]interface{}, verified bool, problems []string) ([]map[string]interface{}, bool, []string) {
	if !verified {
		return kel, false, problems
	}
	rebuilt, ok := RecordsFromVerifiedBytes(kel)
	if !ok {
		return kel, false, append(append([]string(nil), problems...),
			fmt.Sprintf("the log is marked verified but its %d records do not all carry the bytes it was verified by", len(kel)))
	}
	return rebuilt, true, problems
}
