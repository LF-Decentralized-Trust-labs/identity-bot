package keriengine

import (
	"testing"

	"identity-agent-core/drivers"

	keri "github.com/grapeid/keri-go"
)

// A delegated identity whose key this engine does not hold (an asset's) is
// reinstated after a restart with its founding signed again by the signer that
// holds that key, as it was when it was made; the installed signer alone does
// not hold it.
func TestAReinstatedDelegateKeepsItsFoundingSigned(t *testing.T) {
	e := New()
	if _, err := e.CreateInceptionNamed(newKey(t), newKey(t), "root"); err != nil {
		t.Fatal(err)
	}
	child, _ := keri.GenerateSigner(true)
	next, _ := keri.GenerateSigner(true)
	sign := func(raw []byte) (string, error) {
		s, err := child.Sign(raw)
		if err != nil {
			return "", err
		}
		return keri.MatterQB64(keri.CodeEd25519Sig, s)
	}
	cp, np := pubOf(t, child), pubOf(t, next)
	if _, err := e.CreateDelegatedInception(cp, np, "asset", "root", sign); err != nil {
		t.Fatal(err)
	}
	root, _ := e.GetKel("root")
	again := New()
	if _, err := again.ReloadIdentity(&drivers.DriverReloadIdentityRequest{AID: root.AID, KEL: root.KEL, RawEventsB64: root.RawEventsB64, Signatures: root.Signatures}); err != nil {
		t.Fatal(err)
	}
	if _, err := again.ReinstateDelegatedIdentity(cp, np, "asset", root.AID, sign); err != nil {
		t.Fatalf("reinstate: %v", err)
	}
	kel, err := again.GetKel("asset")
	if err != nil {
		t.Fatal(err)
	}
	if len(kel.Signatures) == 0 || len(kel.Signatures[0]) == 0 {
		t.Fatal("the reinstated delegate's founding is held with no signature")
	}
}
