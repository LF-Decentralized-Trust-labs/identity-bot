package drivers

import (
	"encoding/base64"
	"fmt"
	"strings"

	keri "github.com/grapeid/keri-go"
)

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
		// Every signature is carried when the event has several (an identity
		// with more than one key signs with a threshold of them); cesr_signature
		// alone is the first.
		sigs := RecordSignatures(rec)
		if len(sigs) == 0 {
			return nil, fmt.Errorf("event %d carries no signature", i)
		}
		qb := make([]string, 0, len(sigs))
		for _, sig := range sigs {
			at, err := ReadControllerSignature(sig)
			if err != nil {
				return nil, fmt.Errorf("event %d: %w", i, err)
			}
			qb = append(qb, at.QB64)
		}
		m, err := SignedMessage(raw, qb)
		if err != nil {
			return nil, fmt.Errorf("event %d: %w", i, err)
		}
		out = append(out, m)
	}
	return out, nil
}

// RecordSignatures is every controller signature a record carries:
// cesr_signatures when present (one per signing key), otherwise the single
// cesr_signature.
func RecordSignatures(rec map[string]interface{}) []string {
	var out []string
	switch v := rec["cesr_signatures"].(type) {
	case []string:
		out = append(out, v...)
	case []interface{}:
		for _, x := range v {
			if s, _ := x.(string); s != "" {
				out = append(out, s)
			}
		}
	}
	if len(out) == 0 {
		if s, _ := rec["cesr_signature"].(string); s != "" {
			out = []string{s}
		}
	}
	return out
}

// RecordsFromSignedMessages is signed messages (each an event followed by one
// counted group of controller signatures) as the records callers hold: the
// event's bytes and every signature, from which RecordsFromVerifiedBytes builds
// the rest. ok is false when a message is not of that shape, in which case the
// log is not handed on as records.
func RecordsFromSignedMessages(messages [][]byte) ([]map[string]interface{}, bool) {
	recs := make([]map[string]interface{}, 0, len(messages))
	for _, m := range messages {
		raw := eventOf(m)
		if raw == nil {
			return nil, false
		}
		att := string(m[len(raw):])
		if len(att) < 4 || att[:2] != keri.CounterControllerIdxSigs {
			return nil, false
		}
		n := 0
		for _, c := range []byte(att[2:4]) {
			i := strings.IndexByte(b64Digits, c)
			if i < 0 {
				return nil, false
			}
			n = n*64 + i
		}
		att = att[4:]
		if n == 0 {
			return nil, false
		}
		// Each signature is as wide as its own code says, so a log that mixes
		// "A" and "2A" signatures is read whole.
		sigs := make([]string, 0, n)
		for i := 0; i < n; i++ {
			w := indexedSigWidth(att)
			if w == 0 || len(att) < w {
				return nil, false
			}
			sigs = append(sigs, att[:w])
			att = att[w:]
		}
		if len(att) != 0 {
			return nil, false
		}
		recs = append(recs, map[string]interface{}{
			"raw_bytes_b64":   base64.StdEncoding.EncodeToString(raw),
			"cesr_signature":  sigs[0],
			"cesr_signatures": sigs,
		})
	}
	return RecordsFromVerifiedBytes(recs)
}

// indexedSigWidth is the width of the Ed25519 indexed signature at the front of
// s, from its code: 88 for "A" and "B", 92 for "2A" and "2B" (a key at another
// place in its two lists, or an index of 64 or more). 0 for any other code, which
// is not guessed at.
func indexedSigWidth(s string) int {
	switch {
	case strings.HasPrefix(s, "2A"), strings.HasPrefix(s, "2B"):
		return 92
	case strings.HasPrefix(s, "A"), strings.HasPrefix(s, "B"):
		return 88
	}
	return 0
}

const b64Digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// eventOf is the event at the front of a message, up to its closing brace, or
// nil when the message does not begin with a complete event.
func eventOf(m []byte) []byte {
	depth, inStr, esc := 0, false, false
	for i, b := range m {
		if inStr {
			switch {
			case esc:
				esc = false
			case b == '\\':
				esc = true
			case b == '"':
				inStr = false
			}
			continue
		}
		switch b {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return m[:i+1]
			}
		}
	}
	return nil
}
