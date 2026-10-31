package login

import (
	"encoding/base64"
	"testing"
)

// A key log travels inside a signed assertion, so it is read by the same rules
// as the assertion: a field in another case, a field named twice, or a field
// it does not have would let two readers take different events from it.
func TestAKeyLogIsReadOneWayOrNotAtAll(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

	good := `{"raw_events_b64":["e30="],"cesr_signatures":["sig"]}`
	kl, err := DecodeKeyLog(enc(good))
	if err != nil {
		t.Fatalf("a key log in its own form was refused: %v", err)
	}
	if len(kl.RawEventsB64) != 1 || len(kl.CesrSignatures) != 1 {
		t.Fatalf("read as %+v", kl)
	}

	for _, bad := range []string{
		`{"raw_events_b64":["e30="],"Raw_Events_B64":["eA=="],"cesr_signatures":["sig"]}`,
		`{"RAW_EVENTS_B64":["e30="],"cesr_signatures":["sig"]}`,
		`{"raw_events_b64":["e30="],"raw_events_b64":["eA=="],"cesr_signatures":["sig"]}`,
		`{"raw_events_b64":["e30="],"cesr_signatures":["sig"],"extra":1}`,
		"\xef\xbb\xbf" + good,
	} {
		if kl, err := DecodeKeyLog(enc(bad)); err == nil {
			t.Errorf("%q was read as %+v", bad, kl)
		}
	}
}
