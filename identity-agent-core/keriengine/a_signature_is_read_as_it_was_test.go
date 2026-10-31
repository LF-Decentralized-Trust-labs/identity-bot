package keriengine

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"
)

const b64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// sigStarting is 64 random bytes whose padded standard base64 starts with
// prefix.
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

// The engine reads a signature in 0B qb64 or as 64 raw bytes in any base64
// spelling, as it did. A raw one whose padded standard base64 starts with 0B,
// one in 4096, was taken for qb64 and refused; it is read now. Hex is still
// not read, and a second spelling of a qb64 signature is not either.
func TestTheEngineReadsASignatureAsItDid(t *testing.T) {
	for _, prefix := range []string{"", "0B"} {
		sig := sigStarting(t, prefix)
		qb64, _ := keri.MatterQB64(keri.CodeEd25519Sig, sig)
		for _, s := range []string{
			qb64,
			base64.StdEncoding.EncodeToString(sig), base64.RawStdEncoding.EncodeToString(sig),
			base64.URLEncoding.EncodeToString(sig), base64.RawURLEncoding.EncodeToString(sig),
		} {
			got, err := signatureBytes(s)
			if err != nil || !bytes.Equal(got, sig) {
				t.Fatalf("%s read as %x (%v)", s, got, err)
			}
		}
		if _, err := signatureBytes(hex.EncodeToString(sig)); err == nil {
			t.Fatal("a signature in hex was read")
		}
		i := strings.IndexByte(b64url, qb64[2])
		if got, err := signatureBytes(qb64[:2] + string(b64url[i|0x10]) + qb64[3:]); err == nil && bytes.Equal(got, sig) {
			t.Fatal("a second spelling of the signature was read as it")
		}
	}
}
