package secureenclave

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func tpmStandIn() *fakeWrapper {
	return &fakeWrapper{key: bytes.Repeat([]byte{4}, 32), available: true, scheme: tpmSeedScheme}
}

func envelopeWrap(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(rootSeedPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	var env seedEnvelope
	if json.Unmarshal(raw, &env) != nil {
		return "legacy"
	}
	return env.Wrap
}

// A seed that is ALREADY stored unwrapped is not wrapped under the TPM key on
// load unless the operator opts in: the TPM wrapper has not been proven on
// Windows to open after a reboot or as the service user, and a failed open would
// leave every derived key unreadable.
func TestAnExistingSeedIsNotWrappedUnderTheTPMWithoutOptIn(t *testing.T) {
	aDevelopmentBuild(t)
	t.Setenv(TPMWrapExistingSeedEnv, "")
	seed := testSeed()

	t.Run("unwrapped envelope", func(t *testing.T) {
		withWrapper(t, nil)
		dir := t.TempDir()
		if err := StoreDeviceLocalSeed(dir, seed); err != nil {
			t.Fatal(err)
		}
		withWrapper(t, tpmStandIn())
		got, err := LoadRootSeed(dir)
		if err != nil || !bytes.Equal(got, seed) {
			t.Fatalf("load: %v", err)
		}
		if w := envelopeWrap(t, dir); w != seedWrapNone {
			t.Fatalf("an existing seed was wrapped under the TPM without opt-in (%s)", w)
		}
	})

	t.Run("legacy file", func(t *testing.T) {
		withWrapper(t, tpmStandIn())
		dir := t.TempDir()
		p := rootSeedPath(dir)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, seed, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadRootSeed(dir); err != nil {
			t.Fatal(err)
		}
		if w := envelopeWrap(t, dir); w != "legacy" {
			t.Fatalf("a legacy seed was wrapped under the TPM without opt-in (%s)", w)
		}
	})
}

// With the opt-in set, the same upgrade happens.
func TestAnExistingSeedIsWrappedUnderTheTPMWithOptIn(t *testing.T) {
	aDevelopmentBuild(t)
	t.Setenv(TPMWrapExistingSeedEnv, "1")
	withWrapper(t, nil)
	dir := t.TempDir()
	if err := StoreDeviceLocalSeed(dir, testSeed()); err != nil {
		t.Fatal(err)
	}
	withWrapper(t, tpmStandIn())
	if _, err := LoadRootSeed(dir); err != nil {
		t.Fatal(err)
	}
	if w := envelopeWrap(t, dir); w != tpmSeedScheme {
		t.Fatalf("opted in, and the seed was not wrapped (%s)", w)
	}
}

// A NEW seed is wrapped under the TPM with no opt-in: there is no older copy to
// lose.
func TestANewSeedIsWrappedUnderTheTPMWithoutOptIn(t *testing.T) {
	t.Setenv(TPMWrapExistingSeedEnv, "")
	withWrapper(t, tpmStandIn())
	dir := t.TempDir()
	if err := StoreDeviceLocalSeed(dir, testSeed()); err != nil {
		t.Fatal(err)
	}
	if w := envelopeWrap(t, dir); w != tpmSeedScheme {
		t.Fatalf("a new seed was not wrapped (%s)", w)
	}
}

// The gate is the TPM's alone: every other wrapper still upgrades.
func TestTheGateAppliesOnlyToTheTPMWrapper(t *testing.T) {
	t.Setenv(TPMWrapExistingSeedEnv, "")
	if !mayWrapAnExistingSeed(&fakeWrapper{}) || !mayWrapAnExistingSeed(nil) {
		t.Fatal("a non-TPM wrapper was gated")
	}
	if mayWrapAnExistingSeed(tpmStandIn()) {
		t.Fatal("the TPM wrapper was not gated")
	}
}

// Concurrent first callers share one proof; the key is not created twice.
func TestTheProofRunsOnceUnderConcurrentFirstCalls(t *testing.T) {
	var p provenOnce
	var runs atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !p.do(func() bool { runs.Add(1); return true }) {
				t.Error("proof answered false")
			}
		}()
	}
	wg.Wait()
	if runs.Load() != 1 {
		t.Fatalf("the proof ran %d times", runs.Load())
	}
}
