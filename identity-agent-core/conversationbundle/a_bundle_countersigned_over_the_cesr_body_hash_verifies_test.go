package conversationbundle

import (
	"os"
	"testing"
)

// testdata/countersigned-with-cesr-body-hash.json is a genuine export whose
// entries are countersigned over a body_hash written as a CESR digest, the
// form writing moves to in a later release. The published genuine bundle is
// countersigned over the form written now. A verifier accepts both, so a
// bundle exported on either side of the switch verifies.
func TestABundleCountersignedOverTheCESRBodyHashVerifies(t *testing.T) {
	raw, err := os.ReadFile("testdata/countersigned-with-cesr-body-hash.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Read(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r := VerifyAgainst(b, b.Root); !r.Verified || len(r.Messages) != 7 {
		t.Fatalf("a bundle countersigned over the CESR body_hash does not verify:\n%s", faultsOf(r))
	}
}
