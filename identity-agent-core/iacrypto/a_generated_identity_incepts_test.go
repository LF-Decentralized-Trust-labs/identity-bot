//go:build kerigo_pqtest

package iacrypto_test

import (
	"testing"

	"identity-agent-core/iacrypto"
)

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
