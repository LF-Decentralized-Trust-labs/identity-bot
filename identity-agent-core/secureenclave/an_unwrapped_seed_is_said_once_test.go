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

// A store that failed must not claim an unwrapped seed, and must not spend the
// one warning the process has.
//
// Both halves happened. The line was a deferred call registered before the wrap
// block, so it ran on the wrap failure, the round-trip failure and both write
// failures — announcing a seed in the clear that was never written. Holding the
// warning to one per process then made it worse rather than better: that false
// line was the only one the process would emit, so the real unwrapped store
// immediately after it was silent.
func TestAStoreThatFailedClaimsNothingAndSilencesNothing(t *testing.T) {
	if SeedWrapAvailable() || !DetectCapability().RootKeyPermitted() {
		t.Skip("this machine has no unwrapped-seed warning to misfire")
	}

	var out bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(prev) })
	unwrappedSeedWarning = sync.Once{}
	t.Cleanup(func() { unwrappedSeedWarning = sync.Once{} })

	// A path that cannot be written, so the store fails and nothing lands.
	if err := StoreRootSeed("/proc/a-path-that-cannot-be-created", make([]byte, 64)); err == nil {
		t.Skip("this platform allowed the write, so there is no failed store to check")
	}
	if strings.Contains(out.String(), "stored UNWRAPPED") {
		t.Fatalf("a store that wrote nothing announced an unwrapped seed: %s",
			strings.TrimSpace(out.String()))
	}

	// And the real one that follows must still be able to speak.
	out.Reset()
	if err := StoreRootSeed(t.TempDir(), make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "stored UNWRAPPED") {
		t.Fatal("the genuine unwrapped store was silent, because a failed one had spent the warning")
	}
}
