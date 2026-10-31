package asset

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// An enrolment signature arrives over the wire and is read exactly as sent:
// whitespace around it, such as the newline a shell leaves, is not trimmed.
func TestAnEnrolmentSignatureIsNotTrimmed(t *testing.T) {
	sig := make([]byte, ed25519.SignatureSize)
	rand.Read(sig)
	s := base64.StdEncoding.EncodeToString(sig)
	if _, err := decodeEnrolSig(s); err != nil {
		t.Fatalf("the signature did not read: %v", err)
	}
	for _, other := range []string{s + "\n", " " + s, s[:40] + "\n" + s[40:]} {
		if _, err := decodeEnrolSig(other); err == nil {
			t.Errorf("%q was read", other)
		}
	}
}
