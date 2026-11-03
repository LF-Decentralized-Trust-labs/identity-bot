package secureenclave

import (
	"encoding/json"
	"testing"
)

// Component names are map keys, and a key is written the way a value is: a bad
// byte becomes the escape \ufffd, which reads back as the replacement
// character. The payload is made valid before it is signed, so what was signed
// is what a reader re-derives from the record read back.
func TestAPayloadWithABadByteInAComponentNameVerifiesAfterAReload(t *testing.T) {
	p := AttestationPayload{
		Version:    PayloadVersion,
		Components: map[string]string{"bin/caf\xe9": "d1", "ok": "d2"},
	}
	signed, err := CanonicalPayload(p)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var back AttestationPayload
	if err := json.Unmarshal(stored, &back); err != nil {
		t.Fatal(err)
	}
	again, err := CanonicalPayload(back)
	if err != nil {
		t.Fatal(err)
	}
	if string(signed) != string(again) {
		t.Fatalf("signed bytes differ from the reloaded record's:\n %s\n %s", signed, again)
	}
	if _, ok := back.Components["bin/caf\uFFFD"]; !ok {
		t.Fatalf("component name not made valid: %v", back.Components)
	}
}
