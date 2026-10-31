package asset

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// An enrolment signature is read in every base64 spelling and in hex, as it
// was, and nothing of the wrong size is.
func TestAnEnrolmentSignatureIsReadInEverySpelling(t *testing.T) {
	sig := make([]byte, ed25519.SignatureSize)
	rand.Read(sig)
	for _, s := range []string{
		base64.RawURLEncoding.EncodeToString(sig), base64.URLEncoding.EncodeToString(sig),
		base64.RawStdEncoding.EncodeToString(sig), base64.StdEncoding.EncodeToString(sig),
		hex.EncodeToString(sig),
	} {
		got, err := decodeEnrolSig(s)
		if err != nil || !bytes.Equal(got, sig) {
			t.Fatalf("%q read as %x (%v)", s, got, err)
		}
	}
	if _, err := decodeEnrolSig(base64.StdEncoding.EncodeToString(sig[:32])); err == nil {
		t.Fatal("32 bytes were taken for a signature")
	}
}
