package relayproto

import (
	"bytes"
	"strings"
	"testing"
)

// An admission signature is read in its one canonical string.
func TestAnAdmissionSignatureHasOneSpelling(t *testing.T) {
	sig := bytes.Repeat([]byte{0xa5}, 64)
	s := b64.EncodeToString(sig)
	if got, err := signatureOf(s); err != nil || !bytes.Equal(got, sig) {
		t.Fatalf("the canonical signature did not read: %v", err)
	}
	v := strings.IndexByte(b64url, s[85])
	for spare := 1; spare < 16; spare++ {
		other := s[:85] + string(b64url[v&^0xf|spare])
		if _, err := signatureOf(other); err == nil {
			t.Errorf("%q, with spare bits %d, read as the same signature", other, spare)
		}
	}
	for name, other := range map[string]string{
		"padded":     s + "==",
		"line break": s[:40] + "\n" + s[40:],
		"one short":  s[:85],
		"standard":   strings.NewReplacer("-", "+", "_", "/").Replace(s),
	} {
		if other == s {
			continue
		}
		if _, err := signatureOf(other); err == nil {
			t.Errorf("%s: %q was read", name, other)
		}
	}
}
