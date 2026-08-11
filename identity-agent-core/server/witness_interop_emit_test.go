package server

import (
	"fmt"
	"os"
	"testing"
)

// Emits a real witness identifier and receipt for cross-checking against the
// KERI library, which is the side that will verify them in production. Two
// implementations have to agree on these bytes exactly, and nothing else here
// compares them — a Go test verifying a Go signature would agree with itself
// whatever either side did.
//
// Skipped unless asked for, because it exists to produce input for the other
// implementation rather than to assert anything on its own.
func TestEmitWitnessReceiptForCrossCheck(t *testing.T) {
	if os.Getenv("EMIT_WITNESS_VECTOR") == "" {
		t.Skip("set EMIT_WITNESS_VECTOR=1 to emit a vector")
	}
	s := witnessWithSeed(t, 1)
	const said = "EEventSAID0123456789ABCDEFGHIJKLMNOPQRSTUVW"
	aid, sig, err := s.signWitnessReceipt(said)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	fmt.Printf("VECTOR %s %s %s\n", aid, said, sig)
}
