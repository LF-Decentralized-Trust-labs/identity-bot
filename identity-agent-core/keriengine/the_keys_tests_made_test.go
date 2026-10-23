package keriengine

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"sync"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// testKeys are the private keys this package's tests made, by public key, so
// the events they have an engine append are signed by the identity's key as
// the engine requires.
var testKeys sync.Map

func rememberSigner(s *keri.SoftwareSigner) *keri.SoftwareSigner {
	if p, err := s.PublicKey(); err == nil {
		testKeys.Store(p, s)
	}
	return s
}

func rememberKey(pub string, priv ed25519.PrivateKey) {
	testKeys.Store(pub, priv)
}

func TestMain(m *testing.M) {
	testEventSignature = func(aid, key string, raw []byte) (string, error) {
		v, ok := testKeys.Load(key)
		if !ok {
			return "", fmt.Errorf("no test key %q", key)
		}
		var sig []byte
		switch k := v.(type) {
		case *keri.SoftwareSigner:
			var err error
			if sig, err = k.Sign(raw); err != nil {
				return "", err
			}
		case ed25519.PrivateKey:
			sig = ed25519.Sign(k, raw)
		}
		return keri.MatterQB64(keri.CodeEd25519Sig, sig)
	}
	os.Exit(m.Run())
}

// testSigner makes a signer and remembers it.
func testSigner(transferable bool) (*keri.SoftwareSigner, error) {
	s, err := keri.GenerateSigner(transferable)
	if err == nil {
		rememberSigner(s)
	}
	return s, err
}

// No event is appended to an identity's key log unless its current key
// signed it: not an interaction, not an issuance, not a revocation, not a
// delegation's approval, and not with nothing installed to sign.
func TestNoEventIsAppendedUnsigned(t *testing.T) {
	e := New()
	stranger, _ := keri.GenerateSigner(true) // not remembered: its key is not the identity's
	if _, err := e.CreateInceptionNamed(newKey(t), newKey(t), "root"); err != nil {
		t.Fatal(err)
	}
	unsigned := func(aid, key string, raw []byte) (string, error) { return "", fmt.Errorf("no key here") }
	wrongKey := func(aid, key string, raw []byte) (string, error) {
		sig, _ := stranger.Sign(raw)
		return keri.MatterQB64(keri.CodeEd25519Sig, sig)
	}
	seal := []interface{}{map[string]interface{}{"d": "Eanything"}}
	for name, f := range map[string]func(aid, key string, raw []byte) (string, error){"unsigned": unsigned, "another key": wrongKey, "nothing installed": nil} {
		e.SetEventSignature(f)
		before, _ := e.GetKel("root")
		if _, err := e.Interact("root", seal); err == nil {
			t.Fatalf("%s: an interaction was appended", name)
		}
		if _, err := e.InceptRegistry("root"); err == nil {
			t.Fatalf("%s: a registry inception was appended", name)
		}
		if _, err := e.CreateDelegatedInception(newKey(t), newKey(t), "", "root"); err == nil {
			t.Fatalf("%s: a delegation's approval was appended", name)
		}
		if after, _ := e.GetKel("root"); after.EventCount != before.EventCount {
			t.Fatalf("%s: the key log grew", name)
		}
	}
	e.SetEventSignature(testEventSignature)
	if _, err := e.Interact("root", seal); err != nil {
		t.Fatalf("a signed interaction: %v", err)
	}
}
