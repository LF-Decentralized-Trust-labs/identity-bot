package secureenclave

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"testing"
)

// A seed stored in the clear is said once, and it is said at all.
//
// Both halves have failed before, in opposite directions. Saying nothing is
// what let an Apple Silicon machine keep its root seed as a plain file with the
// running system reporting only that key protection could not be determined —
// true, and reassuring, and the wrong thing to be reassured by. Saying it on
// every store is the other failure: ask_sign_layer.go already records that a
// line printed for the rest of a machine's life teaches whoever reads the log
// to skip it, and this is the line that must not be skipped.
func TestAnUnwrappedSeedIsSaidOnceAndNotOncePerStore(t *testing.T) {
	if SeedWrapAvailable() {
		t.Skip("this machine wraps the seed, so there is no warning to count")
	}
	if !DetectCapability().RootKeyPermitted() {
		t.Skip("this machine cannot protect a key, so the warning correctly stays silent")
	}

	// Restored to stderr, not to nil. log.SetOutput(nil) leaves the default
	// logger writing to a nil writer, which breaks every later test in the
	// package that logs anything — and it did.
	var out bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(prev) })

	// Reset, because another test in this package may already have spent it.
	unwrappedSeedWarning = sync.Once{}
	t.Cleanup(func() { unwrappedSeedWarning = sync.Once{} })

	dir := t.TempDir()
	seed := make([]byte, 64)
	for i := 0; i < 3; i++ {
		if err := StoreRootSeed(dir, seed); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
	}

	got := strings.Count(out.String(), "stored UNWRAPPED")
	if got != 1 {
		t.Fatalf("three stores produced %d warnings, want exactly 1", got)
	}

	// And it names which gap this build has, because the remedies are unrelated:
	// a wrapper nobody has written, or one that cannot reach the hardware.
	if !strings.Contains(out.String(), "the gap here") {
		t.Error("the warning does not say whose gap it is")
	}
}
