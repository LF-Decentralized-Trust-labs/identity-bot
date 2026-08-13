package iacrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

// A P-256 key survives the round trip through the wire form.
func TestAP256KeySurvivesTheWireForm(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := CompressP256PublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	qb64, err := P256VerkeyQB64(compressed)
	if err != nil {
		t.Fatal(err)
	}
	if got := qb64[:4]; got != P256VerkeyCode {
		t.Fatalf("encoded under %q, not the P-256 code", got)
	}
	back, err := KeyFromP256VerkeyQB64(qb64)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParseP256PublicKey(back)
	if err != nil {
		t.Fatal(err)
	}
	if pub.X.Cmp(priv.PublicKey.X) != 0 || pub.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Fatal("the key that came back is a different point")
	}
}

// A signature verifies in the fixed-width form KERI carries, not DER.
//
// A signer hands back ASN.1 DER, which is variable length and cannot fit a
// fixed CESR code. Getting that conversion wrong produces a signature that
// looks right and verifies nowhere.
func TestASignatureVerifiesInTheFormKeriCarries(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	msg := []byte("what the machine is signing")
	sum := sha256.Sum256(msg)

	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	if !VerifyP256(&priv.PublicKey, msg, sig) {
		t.Fatal("a signature this key just made did not verify")
	}
	// And it is actually checking something.
	sig[0] ^= 0xff
	if VerifyP256(&priv.PublicKey, msg, sig) {
		t.Fatal("a tampered signature verified")
	}
}

// A point that is not on the curve is refused, not accepted as a key that
// happens to verify nothing.
func TestAPointOffTheCurveIsRefused(t *testing.T) {
	bad := make([]byte, P256PublicKeySize)
	bad[0] = 0x02 // a plausible parity byte, and the rest is not an x on P-256
	for i := 1; i < len(bad); i++ {
		bad[i] = 0xff
	}
	if _, err := ParseP256PublicKey(bad); err == nil {
		t.Fatal("a point that is not on P-256 was accepted as a key")
	}
}

// The wrong length is refused rather than padded or truncated.
func TestAP256KeyOfTheWrongLengthIsRefused(t *testing.T) {
	for _, n := range []int{0, 32, 64, 65} {
		if _, err := P256VerkeyQB64(make([]byte, n)); err == nil {
			t.Errorf("%d bytes was accepted as a compressed P-256 key", n)
		}
	}
}
