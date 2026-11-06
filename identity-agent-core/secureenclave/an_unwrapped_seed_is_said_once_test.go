package secureenclave

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
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
//
// An unwrapped store only happens in a development build now (production refuses
// it), so the machine is stood up the same way on every platform: hardware that
// can protect a key, no wrapper that uses it, a development build.
func TestAnUnwrappedSeedIsSaidOnceAndNotOncePerStore(t *testing.T) {
	standAnUnwrappedMachine(t)

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
		if err := StoreDeviceLocalSeed(dir, seed); err != nil {
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
	standAnUnwrappedMachine(t)

	var out bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(prev) })
	unwrappedSeedWarning = sync.Once{}
	t.Cleanup(func() { unwrappedSeedWarning = sync.Once{} })

	// A path that cannot be written (a regular file where the directory must
	// go), so the store fails and nothing lands.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := StoreDeviceLocalSeed(blocker, make([]byte, 64)); err == nil {
		t.Fatal("a store under a regular file succeeded")
	}
	if strings.Contains(out.String(), "stored UNWRAPPED") {
		t.Fatalf("a store that wrote nothing announced an unwrapped seed: %s",
			strings.TrimSpace(out.String()))
	}

	// And the real one that follows must still be able to speak.
	out.Reset()
	if err := StoreDeviceLocalSeed(t.TempDir(), make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "stored UNWRAPPED") {
		t.Fatal("the genuine unwrapped store was silent, because a failed one had spent the warning")
	}
}

// standAnUnwrappedMachine is a development build on hardware that can protect a
// key, with no seed wrapper using it: the one state in which a seed is stored
// unwrapped and the warning applies.
func standAnUnwrappedMachine(t *testing.T) {
	t.Helper()
	aDevelopmentBuild(t)
	r1 := UseCapabilityDetector(func() Capability { return Capability{Status: Usable, Kind: KindAppleEnclave} })
	r2 := UseSeedWrapper(nil)
	t.Cleanup(func() { r2(); r1() })
}

// In a production build the same machine is refused: nothing is written, and the
// one warning is not spent on a store that never happened.
func TestAnUnwrappedStoreIsRefusedInProductionAndSaysNothing(t *testing.T) {
	standAnUnwrappedMachine(t)
	isDevBuild = func() bool { return false }

	var out bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(prev) })
	unwrappedSeedWarning = sync.Once{}
	t.Cleanup(func() { unwrappedSeedWarning = sync.Once{} })

	dir := t.TempDir()
	if err := StoreDeviceLocalSeed(dir, make([]byte, 64)); !IsRootSeedRefusal(err) {
		t.Fatalf("a production build stored an unwrapped device seed: %v", err)
	}
	if _, err := os.Stat(rootSeedPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("a seed file exists after the refusal: %v", err)
	}
	if strings.Contains(out.String(), "stored UNWRAPPED") {
		t.Fatalf("a refused store announced an unwrapped seed: %s", out.String())
	}
}

// The load-time rule, on every platform: a production build never serves a seed
// that is already stored unwrapped, whatever the platform and whether or not the
// opt-in to wrap it is set (refusing to use a seed does not touch it). A
// development build serves it.
func TestAProductionBuildNeverServesAnUnwrappedSeedOnAnyPlatform(t *testing.T) {
	for _, tc := range []struct {
		name  string
		phone bool
		w     SeedWrapper
		optIn string
	}{
		{"no wrapper, desktop", false, nil, ""},
		{"TPM wrapper, no opt-in", false, tpmStandIn(), ""},
		{"working wrapper that was not used", false, &fakeWrapper{key: bytes.Repeat([]byte{5}, 32), available: false, scheme: "fake"}, ""},
		{"no wrapper, phone", true, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(TPMWrapExistingSeedEnv, tc.optIn)
			r1 := UseCapabilityDetector(func() Capability { return Capability{Status: Usable, Kind: KindAppleEnclave} })
			r2 := UseSeedWrapper(nil) // the seed was stored before any wrapper was usable
			pd, pp := isDevBuild, thisIsAPhone
			thisIsAPhone = func() bool { return tc.phone }
			t.Cleanup(func() { isDevBuild, thisIsAPhone = pd, pp; r2(); r1() })

			dir := t.TempDir()
			isDevBuild = func() bool { return true }
			if err := StoreDeviceLocalSeed(dir, testSeed()); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(rootSeedPath(dir))
			r2()
			r2 = UseSeedWrapper(tc.w)

			isDevBuild = func() bool { return false }
			if _, err := LoadRootSeed(dir); !IsRootSeedRefusal(err) {
				t.Fatalf("production served an unwrapped seed: %v", err)
			}
			if after, _ := os.ReadFile(rootSeedPath(dir)); !bytes.Equal(before, after) {
				t.Fatal("refusing to use the seed changed the file")
			}

			isDevBuild = func() bool { return true }
			if _, err := LoadRootSeed(dir); err != nil {
				t.Fatalf("a development build was refused: %v", err)
			}
		})
	}
}

// The warning asks the same capability seam everything else in this package
// asks, not the hardware directly. A machine this package has been told cannot
// protect a key has no "could have protected it and did not" to report, so it
// says nothing; together with TestAnUnwrappedSeedIsSaidOnceAndNotOncePerStore
// (told it can, so it speaks) this fails on any host whose real answer
// disagrees with one of the two, if the warning goes back to asking the hardware.
func TestTheUnwrappedWarningAsksTheCapabilitySeamNotTheHardware(t *testing.T) {
	for _, st := range []Status{Absent, Present, Unknown} {
		t.Run(string(st), func(t *testing.T) {
			aDevelopmentBuild(t)
			r1 := UseCapabilityDetector(func() Capability { return Capability{Status: st} })
			r2 := UseSeedWrapper(nil)
			t.Cleanup(func() { r2(); r1() })

			var out bytes.Buffer
			prev := log.Writer()
			log.SetOutput(&out)
			t.Cleanup(func() { log.SetOutput(prev) })
			unwrappedSeedWarning = sync.Once{}
			t.Cleanup(func() { unwrappedSeedWarning = sync.Once{} })

			if err := StoreDeviceLocalSeed(t.TempDir(), make([]byte, 64)); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), "stored UNWRAPPED") {
				t.Fatalf("told the machine cannot protect a key (%s), the warning said it could: %s",
					st, strings.TrimSpace(out.String()))
			}
		})
	}
}
