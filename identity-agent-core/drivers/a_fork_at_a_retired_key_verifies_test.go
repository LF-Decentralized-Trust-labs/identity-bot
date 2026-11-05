package drivers_test

import (
	"testing"

	"identity-agent-core/drivers/signedlog"
)

// What the store has to defend against, proved against the engine's validator
// rather than assumed: with keys K1 -> K2 -> K3, somebody who holds only the
// retired K2 can sign interaction events of their own after the K2 rotation. The
// result is a log that holds together, is signed by the keys it declares, and
// derives the right identifier, so the engine says "verified" and names K2 as
// the current key. The validator cannot tell it from the real history, which is
// why the store must refuse to let it replace the longer one it already holds.
func TestAForkSignedByARetiredKeyIsVerifiedByTheEngine(t *testing.T) {
	keys := signedlog.NewKeys(t, 3)
	real := signedlog.Incept(t, keys).Rotate() // K1, K2
	atK2 := real.Fork()
	real.Rotate() // K3: the owner's real, longer history

	fork := atK2.Fork().Interact("mine").Interact("also mine")

	if v := real.Verdict(); !v.KelVerified || v.CurrentPublicKey != keys.Pub(2) {
		t.Fatalf("the real log: verified=%v key=%q errors=%v", v.KelVerified, v.CurrentPublicKey, v.ValidationErrors)
	}
	v := fork.Verdict()
	if !v.KelVerified {
		t.Fatalf("the engine refuses the fork, so the store need not (errors: %v)", v.ValidationErrors)
	}
	if v.CurrentPublicKey != keys.Pub(1) {
		t.Fatalf("the fork's key is %q, want the retired K2 %q", v.CurrentPublicKey, keys.Pub(1))
	}
	if fork.Len() < real.Len() {
		t.Fatalf("the fork must be as long as the real log to defeat a count: %d < %d", fork.Len(), real.Len())
	}
}
