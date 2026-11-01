package drivers

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"
)

const b64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func sigStarting(t *testing.T, prefix string) []byte {
	t.Helper()
	for i := 0; i < 1_000_000; i++ {
		sig := make([]byte, 64)
		rand.Read(sig)
		if strings.HasPrefix(base64.StdEncoding.EncodeToString(sig), prefix) {
			return sig
		}
	}
	t.Fatalf("none starting %q", prefix)
	return nil
}

func indexed(code byte, index int, sig []byte) string {
	s := base64.RawURLEncoding.EncodeToString(append([]byte{0, 0}, sig...))
	return string(code) + string(b64url[index]) + s[2:]
}

// A controller signature is read in the forms it was: 0B, indexed with code
// A at the first key, and raw standard base64. A raw one starting with A, one
// in 64, was taken for an indexed signature and refused; it is read now. The
// unindexed forms are indexed at the first key, where the agent's own
// single-key identity keeps it. An indexed signature naming another place, or
// the current-list code B, is read as written and judged by the log verifier.
// A second spelling of the 0B and indexed forms is still refused.
func TestAControllerSignatureIsReadAsItWas(t *testing.T) {
	for _, prefix := range []string{"", "A"} {
		sig := sigStarting(t, prefix)
		qb64, _ := keri.MatterQB64(keri.CodeEd25519Sig, sig)
		for _, s := range []string{qb64, indexed('A', 0, sig), base64.StdEncoding.EncodeToString(sig)} {
			got, err := ReadControllerSignature(s)
			if err != nil || !bytes.Equal(got.Raw, sig) || got.At != keri.SamePlace(0) {
				t.Fatalf("%s read as %x at %+v (%v)", s, got.Raw, got.At, err)
			}
		}
		for name, c := range map[string]struct {
			s  string
			at keri.SignaturePlace
		}{
			"indexed to the second key": {indexed('A', 1, sig), keri.SamePlace(1)},
			"current-list code B":       {indexed('B', 0, sig), keri.SignaturePlace{CurrentOnly: true}},
		} {
			got, err := ReadControllerSignature(c.s)
			if err != nil || !bytes.Equal(got.Raw, sig) || got.At != c.at {
				t.Errorf("%s: read as %+v (%v)", name, got.At, err)
			}
		}
		for _, s := range []string{qb64, indexed('A', 0, sig)} {
			i := strings.IndexByte(b64url, s[2])
			if got, err := ReadControllerSignature(s[:2] + string(b64url[i|0x10]) + s[3:]); err == nil && bytes.Equal(got.Raw, sig) {
				t.Errorf("a second spelling of %s was read as it", s)
			}
		}
	}
}
