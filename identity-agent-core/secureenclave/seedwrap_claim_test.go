package secureenclave

import (
	"encoding/json"
	"os"
	"testing"
)

// What SeedWrapAvailable reports and what is actually on disk must never
// disagree. Anything that tells a user their keys are hardware-protected reads
// this, so a mismatch here is a false security indicator — the kind somebody
// relies on instead of going to check.
func TestTheWrapClaimMatchesWhatIsOnDisk(t *testing.T) {
	readEnvelope := func(t *testing.T, dir string) seedEnvelope {
		t.Helper()
		b, err := os.ReadFile(rootSeedPath(dir))
		if err != nil {
			t.Fatalf("reading the stored seed: %v", err)
		}
		var env seedEnvelope
		if err := json.Unmarshal(b, &env); err != nil {
			t.Fatalf("the stored seed is not an envelope: %v", err)
		}
		return env
	}

	t.Run("no wrapper: claims nothing, and stores nothing wrapped", func(t *testing.T) {
		withWrapper(t, nil)
		dir := t.TempDir()
		if err := StoreRootSeed(dir, testSeed()); err != nil {
			t.Fatalf("storing: %v", err)
		}
		if SeedWrapAvailable() {
			t.Error("claimed the seed is hardware-wrapped with no wrapper present")
		}
		if got := SeedWrapScheme(); got != seedWrapNone {
			t.Errorf("scheme = %q, want %q", got, seedWrapNone)
		}
		if env := readEnvelope(t, dir); env.Wrap != seedWrapNone {
			t.Errorf("on disk wrap = %q, want %q — the claim and the file disagree", env.Wrap, seedWrapNone)
		}
	})

	// A wrapper that is present but NOT usable is the case that produced the
	// bug: hardware exists, so something concluded it was in use.
	t.Run("wrapper present but unusable: still claims nothing", func(t *testing.T) {
		withWrapper(t, &fakeWrapper{key: make([]byte, 32), available: false})
		dir := t.TempDir()
		if err := StoreRootSeed(dir, testSeed()); err != nil {
			t.Fatalf("storing: %v", err)
		}
		if SeedWrapAvailable() {
			t.Error("claimed hardware backing from a wrapper that reports itself unusable")
		}
		if env := readEnvelope(t, dir); env.Wrap != seedWrapNone {
			t.Errorf("on disk wrap = %q, want %q", env.Wrap, seedWrapNone)
		}
	})

	t.Run("usable wrapper: claims it, and the disk agrees", func(t *testing.T) {
		w := &fakeWrapper{key: make([]byte, 32), available: true}
		withWrapper(t, w)
		dir := t.TempDir()
		if err := StoreRootSeed(dir, testSeed()); err != nil {
			t.Fatalf("storing: %v", err)
		}
		if !SeedWrapAvailable() {
			t.Error("a usable wrapper was not reported")
		}
		if got := SeedWrapScheme(); got != w.Scheme() {
			t.Errorf("scheme = %q, want %q", got, w.Scheme())
		}
		env := readEnvelope(t, dir)
		if env.Wrap != w.Scheme() {
			t.Errorf("on disk wrap = %q, want %q", env.Wrap, w.Scheme())
		}
		// And the strong form: the plaintext seed must not be sitting in the file.
		if string(env.Blob) == string(testSeed()) {
			t.Error("the seed was stored in the clear despite a usable wrapper")
		}
	})
}
