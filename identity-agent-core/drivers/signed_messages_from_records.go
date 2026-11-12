package drivers

import "fmt"

// SignedMessagesFromRecords is a key log's records as the messages
// keri.ValidateSignedKEL judges: each event's raw bytes with its controller
// signature attached, read from raw_bytes_b64 and cesr_signature and from
// nothing else (a field served beside the bytes is not covered by a proof).
//
// It is for the caller that has only records. The error names the first event
// that cannot be proven (no bytes, no signature, or a signature that does not
// read), so a caller can say "parsed records only" instead of passing a log
// off as proven.
func SignedMessagesFromRecords(records []map[string]interface{}) ([][]byte, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("the log has no events")
	}
	out := make([][]byte, 0, len(records))
	for i, rec := range records {
		rawB64, _ := rec["raw_bytes_b64"].(string)
		if rawB64 == "" {
			return nil, fmt.Errorf("event %d carries no signed bytes, only parsed fields", i)
		}
		raw, err := DecodeRawBytes(rawB64)
		if err != nil || len(raw) == 0 {
			return nil, fmt.Errorf("event %d: its bytes do not decode", i)
		}
		sig, _ := rec["cesr_signature"].(string)
		if sig == "" {
			return nil, fmt.Errorf("event %d carries no signature", i)
		}
		at, err := ReadControllerSignature(sig)
		if err != nil {
			return nil, fmt.Errorf("event %d: %w", i, err)
		}
		m, err := SignedMessage(raw, []string{at.QB64})
		if err != nil {
			return nil, fmt.Errorf("event %d: %w", i, err)
		}
		out = append(out, m)
	}
	return out, nil
}
