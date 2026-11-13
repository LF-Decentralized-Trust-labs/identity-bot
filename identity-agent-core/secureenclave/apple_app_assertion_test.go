package secureenclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

// anAssertion is an App Attest assertion made the way Apple's steps say, with a
// software key standing in for the Secure Enclave's.
func anAssertion(t *testing.T, k *ecdsa.PrivateKey, appID string, counter uint32, clientDataHash []byte) []byte {
	t.Helper()
	rp := sha256.Sum256([]byte(appID))
	authData := append(append([]byte{}, rp[:]...), 0, byte(counter>>24), byte(counter>>16), byte(counter>>8), byte(counter))
	nonce := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash...))
	digest := sha256.Sum256(nonce[:])
	sig, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return cat(cborHead(5, 2), cbText("signature"), cbBytes(sig), cbText("authenticatorData"), cbBytes(authData))
}

func TestAnAppleAssertionIsCheckedForTheKeyTheAppAndTheStatement(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const app = "TEAM123456.org.example.portal"
	h := sha256.Sum256([]byte("the statement"))
	good := anAssertion(t, k, app, 7, h[:])

	if n, err := VerifyAppleAssertion(good, h[:], &k.PublicKey, app); err != nil || n != 7 {
		t.Fatalf("a good assertion: counter %d, %v", n, err)
	}
	wrongHash := sha256.Sum256([]byte("another statement"))
	for name, c := range map[string]struct {
		assertion []byte
		hash      []byte
		key       *ecdsa.PublicKey
		app       string
	}{
		"another statement":        {good, wrongHash[:], &k.PublicKey, app},
		"another key":              {good, h[:], &other.PublicKey, app},
		"another app":              {good, h[:], &k.PublicKey, "TEAM123456.org.evil"},
		"signed by another key":    {anAssertion(t, other, app, 7, h[:]), h[:], &k.PublicKey, app},
		"not CBOR":                 {[]byte("x"), h[:], &k.PublicKey, app},
		"a plain signature":        {[]byte{0x01}, h[:], &k.PublicKey, app},
		"a hash of the wrong size": {good, h[:8], &k.PublicKey, app},
		"no app":                   {good, h[:], &k.PublicKey, ""},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyAppleAssertion(c.assertion, c.hash, c.key, c.app); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
