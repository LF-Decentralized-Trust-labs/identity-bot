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
// in 64, was taken for an indexed signature and refused; it is read now.
// Indexed to another key, the current-list code B, and a second spelling of
// any of them are still refused.
func TestAControllerSignatureIsReadAsItWas(t *testing.T) {
	for _, prefix := range []string{"", "A"} {
		sig := sigStarting(t, prefix)
		qb64, _ := keri.MatterQB64(keri.CodeEd25519Sig, sig)
		for _, s := range []string{qb64, indexed('A', 0, sig), base64.StdEncoding.EncodeToString(sig)} {
			got, err := decodeCesrSignature(s)
			if err != nil || !bytes.Equal(got, sig) {
				t.Fatalf("%s read as %x (%v)", s, got, err)
			}
		}
		for name, s := range map[string]string{
			"indexed to the second key": indexed('A', 1, sig),
			"current-list code B":       indexed('B', 0, sig),
		} {
			if _, err := decodeCesrSignature(s); err == nil {
				t.Errorf("%s: read", name)
			}
		}
		for _, s := range []string{qb64, indexed('A', 0, sig)} {
			i := strings.IndexByte(b64url, s[2])
			if got, err := decodeCesrSignature(s[:2] + string(b64url[i|0x10]) + s[3:]); err == nil && bytes.Equal(got, sig) {
				t.Errorf("a second spelling of %s was read as it", s)
			}
		}
	}
}
