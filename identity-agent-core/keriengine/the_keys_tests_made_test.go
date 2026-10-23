package keriengine

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"identity-agent-core/drivers"

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
		if _, err := e.IssueCredential("root", map[string]interface{}{"role": "engineer"}, testSchemaSAID(t), "", nil); err == nil {
			t.Fatalf("%s: an issuance outside a registry was appended", name)
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

// A log reloaded without the bytes it was published as is not trusted to say
// which key is in force: the key given with it is used, and with none given
// nothing is appended.
func TestAnUncheckedLogDoesNotNameTheKeyInForce(t *testing.T) {
	e := New()
	root, err := e.CreateInceptionNamed(newKey(t), newKey(t), "root")
	if err != nil {
		t.Fatal(err)
	}
	kel, _ := e.GetKel("root")
	// The parsed events alone, with their key edited: nothing checks them.
	edited := make([]map[string]interface{}, len(kel.KEL))
	for i, ev := range kel.KEL {
		c := map[string]interface{}{}
		for k, v := range ev {
			c[k] = v
		}
		edited[i] = c
	}
	stranger := newKey(t) // remembered, so it could sign if it were believed
	edited[0]["k"] = []interface{}{stranger}
	seal := []interface{}{map[string]interface{}{"d": root.AID}}

	noKey := New()
	if _, err := noKey.ReloadIdentity(&drivers.DriverReloadIdentityRequest{AID: kel.AID, KEL: edited, LastSAID: root.AID}); err != nil {
		t.Fatal(err)
	}
	if _, err := noKey.InteractKept(kel.AID, seal, nil); err == nil || !strings.Contains(err.Error(), "not known here") {
		t.Fatalf("an unchecked log's key was believed: %v", err)
	}
	given := New()
	if _, err := given.ReloadIdentity(&drivers.DriverReloadIdentityRequest{AID: kel.AID, KEL: edited, LastSAID: root.AID, PublicKey: stranger}); err != nil {
		t.Fatal(err)
	}
	ownKey := New()
	if _, err := ownKey.ReloadIdentity(&drivers.DriverReloadIdentityRequest{AID: kel.AID, KEL: kel.KEL, RawEventsB64: kel.RawEventsB64}); err != nil {
		t.Fatal(err)
	}
	if _, err := ownKey.InteractKept(kel.AID, seal, nil); err != nil {
		t.Fatalf("a checked log's key in force: %v", err)
	}
}

func testSchemaSAID(t *testing.T) string {
	t.Helper()
	s, err := keri.Blake3SAID([]byte("a test schema"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A multisig rotation must carry the key the previous event committed to;
// others may join it.
func TestAMultisigRotationKeepsTheCommitment(t *testing.T) {
	e := New()
	next := newKey(t)
	if _, err := e.CreateInceptionNamed(newKey(t), next, "root"); err != nil {
		t.Fatal(err)
	}
	d1, _ := keri.NextDigest(newKey(t))
	d2, _ := keri.NextDigest(newKey(t))
	if _, err := e.RotateToMultisig("root", []string{newKey(t), newKey(t)}, []string{d1, d2}, "1", "1", nil); err == nil {
		t.Fatal("a rotation to keys the identity never committed to was appended")
	}
	if _, err := e.RotateToMultisig("root", []string{next, newKey(t)}, []string{d1, d2}, "1", "1", nil); err != nil {
		t.Fatalf("a rotation carrying the committed key: %v", err)
	}
}

// A log reloaded with the bytes of only some of its events does not name its
// key in force from those: here the inception's key, which a rotation since
// replaced.
func TestAPartlyCheckedLogDoesNotNameAStaleKey(t *testing.T) {
	e := New()
	first, second, third := newKey(t), newKey(t), newKey(t)
	root, err := e.CreateInceptionNamed(first, second, "root")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.RotateAid("root", second, third); err != nil {
		t.Fatal(err)
	}
	kel, _ := e.GetKel("root")
	partial := []string{kel.RawEventsB64[0], ""}
	again := New()
	if _, err := again.ReloadIdentity(&drivers.DriverReloadIdentityRequest{AID: kel.AID, KEL: kel.KEL, RawEventsB64: partial, LastSAID: kel.KEL[1]["d"].(string), SequenceNumber: 1}); err != nil {
		t.Fatal(err)
	}
	seal := []interface{}{map[string]interface{}{"d": root.AID}}
	if _, err := again.InteractKept(kel.AID, seal, nil); err == nil {
		t.Fatal("an interaction was appended under the key a rotation replaced")
	}
}
