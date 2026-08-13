package login

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"identity-agent-core/iacrypto"
)

func p256Signed(t *testing.T, body string) (key, sig string, priv *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := iacrypto.CompressP256PublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err = iacrypto.P256VerkeyQB64(compressed)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	sig, err = iacrypto.MatterFixedQB64(iacrypto.P256SignatureCode, raw)
	if err != nil {
		t.Fatal(err)
	}
	return key, sig, priv
}

// A machine's P-256 signature verifies.
func TestAP256SignatureVerifies(t *testing.T) {
	body := "what the machine signed"
	key, sig, _ := p256Signed(t, body)

	ok, err := VerifyStringAnyCurve(body, sig, key)
	if err != nil {
		t.Fatalf("a valid P-256 signature errored: %v", err)
	}
	if !ok {
		t.Fatal("a valid P-256 signature did not verify")
	}
}

// And Ed25519 keeps working, byte for byte, because everything that is not a
// machine still signs with it.
func TestEd25519StillVerifiesUnchanged(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := "what a person signed"
	sig, err := SignString(body, priv.Seed())
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyStringAnyCurve(body, sig, iacrypto.VerkeyQB64(pub))
	if err != nil || !ok {
		t.Fatalf("an Ed25519 signature stopped verifying: ok=%v err=%v", ok, err)
	}
}

// Signing a different body does not verify — so the test above is checking
// something.
func TestADifferentBodyDoesNotVerifyOnEitherCurve(t *testing.T) {
	key, sig, _ := p256Signed(t, "the original")
	if ok, _ := VerifyStringAnyCurve("something else", sig, key); ok {
		t.Error("a P-256 signature verified against a body it was not made over")
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	edSig, _ := SignString("the original", priv.Seed())
	if ok, _ := VerifyStringAnyCurve("something else", edSig, iacrypto.VerkeyQB64(pub)); ok {
		t.Error("an Ed25519 signature verified against a body it was not made over")
	}
}

// A P-256 key with an Ed25519 signature is refused rather than quietly failing
// somewhere further in.
func TestACurveMismatchIsRefusedWithItsReason(t *testing.T) {
	key, _, _ := p256Signed(t, "x")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	edSig, _ := SignString("x", priv.Seed())

	ok, err := VerifyStringAnyCurve("x", edSig, key)
	if ok {
		t.Fatal("an Ed25519 signature was accepted for a P-256 key")
	}
	if err == nil {
		t.Fatal("refused without saying why the two do not go together")
	}
}
