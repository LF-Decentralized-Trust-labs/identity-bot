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

// A record written when an encoder spelled a bad byte as the escape � is
// built here by hand, not by the encoder, so this means the same on every Go
// release: it reads back as the replacement character and its canonical bytes
// are those of the record written with the character itself.
func TestAPayloadWrittenWithTheEscapedSpellingHasTheSameSignedBytes(t *testing.T) {
	escaped := []byte(`{"Components":{"bin/caf�":"d1"}}`)
	raw := []byte("{\"Components\":{\"bin/caf�\":\"d1\"}}")
	var a, b AttestationPayload
	if err := json.Unmarshal(escaped, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	ca, err := CanonicalPayload(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := CanonicalPayload(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca) != string(cb) {
		t.Fatalf("differ:\n %s\n %s", ca, cb)
	}
	if _, ok := a.Components["bin/caf�"]; !ok {
		t.Fatalf("escaped key not read as the replacement character: %v", a.Components)
	}
}

func TestTwoComponentNamesThatDifferOnlyInBadBytesAreRefused(t *testing.T) {
	p := AttestationPayload{Version: PayloadVersion, Components: map[string]string{"a\xff": "d1", "a\xfe": "d2"}}
	if _, err := CanonicalPayload(p); err == nil {
		t.Fatal("two components merged into one without an error")
	}
}
