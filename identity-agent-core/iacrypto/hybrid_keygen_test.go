package iacrypto_test

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"identity-agent-core/iacrypto"
)

// The property that distinguishes a key from a placeholder: it can sign, and
// the signature verifies under the published public key.
//
// The path this replaces filled the post-quantum fields with random bytes. Those
// are the right length and encode without complaint, and an identity founded on
// one carries a post-quantum key that can never be used — which is worse than
// having no post-quantum key, because it looks like protection.
func TestGeneratedHybridKeysCanActuallySign(t *testing.T) {
	material, secrets, err := iacrypto.GenerateHybridKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("an event this identity is asserting")

	t.Run("classical half", func(t *testing.T) {
		priv := ed25519.NewKeyFromSeed(secrets.Ed25519Seed)
		sig := ed25519.Sign(priv, msg)
		if !ed25519.Verify(material.Ed25519SigningRaw, msg, sig) {
			t.Error("the published Ed25519 key does not verify a signature made with " +
				"the secret returned beside it")
		}
	})

	t.Run("post-quantum half", func(t *testing.T) {
		var seed [mldsa65.SeedSize]byte
		copy(seed[:], secrets.MLDSA65Seed)
		_, sk := mldsa65.NewKeyFromSeed(&seed)

		sig := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(sk, msg, nil, false, sig); err != nil {
			t.Fatal(err)
		}
		var pk mldsa65.PublicKey
		if err := pk.UnmarshalBinary(material.MLDSA65SigningRaw); err != nil {
			t.Fatalf("the published ML-DSA key is not a readable public key: %v", err)
		}
		if !mldsa65.Verify(&pk, msg, nil, sig) {
			t.Error("the published ML-DSA-65 key does not verify a signature made with " +
				"the secret returned beside it — this is exactly the failure that " +
				"random placeholder bytes produce")
		}
	})
}

// Pre-rotation only protects anything if the next keys are real and distinct.
func TestTheNextKeysAreRealAndDifferent(t *testing.T) {
	m, s, err := iacrypto.GenerateHybridKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(m.Ed25519SigningRaw, m.NextEd25519SigningRaw) {
		t.Error("the identity commits to the key it is already using")
	}
	if bytes.Equal(m.MLDSA65SigningRaw, m.NextMLDSA65SigningRaw) {
		t.Error("the identity commits to the post-quantum key it is already using")
	}
	if bytes.Equal(s.Ed25519Seed, s.NextEd25519Seed) {
		t.Error("the current and next classical secrets are the same")
	}
	// The next key must be usable when its turn comes, or the identity can
	// never rotate.
	priv := ed25519.NewKeyFromSeed(s.NextEd25519Seed)
	if !bytes.Equal(priv.Public().(ed25519.PublicKey), m.NextEd25519SigningRaw) {
		t.Error("the next secret does not correspond to the next published key")
	}
}

// Two identities must not be the same identity.
func TestGeneratedIdentitiesAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		m, _, err := iacrypto.GenerateHybridKeyMaterial()
		if err != nil {
			t.Fatal(err)
		}
		k := string(m.Ed25519SigningRaw) + string(m.MLDSA65SigningRaw)
		if seen[k] {
			t.Fatal("two generated identities share key material")
		}
		seen[k] = true
	}
}

// A generated identity must produce an inception event, and the event must
// carry the keys that were generated.
func TestAGeneratedIdentityIncepts(t *testing.T) {
	m, _, err := iacrypto.GenerateHybridKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	res, err := iacrypto.BuildHybridInception(m)
	if err != nil {
		t.Fatalf("a real hybrid identity could not be incepted: %v", err)
	}
	if res.AID == "" || res.SAID == "" {
		t.Fatal("the inception produced no identifier")
	}
	if res.CipherSuite != iacrypto.CipherSuiteIAHybrid1 {
		t.Errorf("cipher suite is %q", res.CipherSuite)
	}
	if !iacrypto.IsHybridIdentity(res.InceptionEvent) {
		t.Error("the event does not read as a hybrid identity")
	}
	if n := iacrypto.SigningKeyCount(res.InceptionEvent); n != 2 {
		t.Errorf("the event declares %d signing keys, expected the classical and the "+
			"post-quantum one", n)
	}
}
