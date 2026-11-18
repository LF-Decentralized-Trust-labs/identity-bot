package secureenclave

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"strings"
	"testing"
)

// An RSA attestation key shorter than 2048 bits is refused, though its signature checks.
func TestAnRSAAttestationKeyShorterThan2048BitsIsRefused(t *testing.T) {
	msg := []byte("a certify's attested bytes")
	sign := func(bits int) (*tpmPublic, []byte) {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		d := sha256.Sum256(msg)
		s, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
		if err != nil {
			t.Fatal(err)
		}
		sig := []byte{byte(tpmAlgRSASSA >> 8), byte(tpmAlgRSASSA), byte(tpmAlgSHA256 >> 8), byte(tpmAlgSHA256), byte(len(s) >> 8), byte(len(s))}
		return &tpmPublic{typ: tpmAlgRSA, scheme: tpmAlgNull, mod: k.N.Bytes(), exp: 0}, append(sig, s...)
	}
	ak, sig := sign(2048)
	if err := verifyTPMSignature(ak, msg, sig); err != nil {
		t.Fatalf("a 2048-bit key's signature was refused: %v", err)
	}
	ak, sig = sign(1536)
	if err := verifyTPMSignature(ak, msg, sig); err == nil || !strings.Contains(err.Error(), "2048") {
		t.Fatalf("a 1536-bit key was accepted, or refused for another reason: %v", err)
	}
}
