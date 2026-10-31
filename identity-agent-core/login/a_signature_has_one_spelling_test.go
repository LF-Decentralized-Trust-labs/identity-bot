package login

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

const b64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// A signature is read in the one form this signs in, 0B qb64, and in no
// second spelling of it. Characters added after it and the lead bits its
// third character carries were both read before, so one signature had many
// strings that verified.
func TestASignatureHasOneSpelling(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig, err := SignString("a body", priv.Seed())
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := verifyUTF8("a body", sig, pub); err != nil || !ok {
		t.Fatalf("the genuine signature did not verify: %v", err)
	}
	i := strings.IndexByte(b64url, sig[2])
	for name, s := range map[string]string{
		"characters added": sig + "AAAA",
		"lead bits set":    sig[:2] + string(b64url[i|0x10]) + sig[3:],
		"one missing":      sig[:87],
	} {
		if ok, _ := verifyUTF8("a body", s, pub); ok {
			t.Errorf("%s: a second spelling of the signature verified", name)
		}
	}
}
