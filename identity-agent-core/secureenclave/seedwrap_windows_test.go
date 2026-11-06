//go:build windows

package secureenclave

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// These run against the REAL TPM through the Platform Crypto Provider and skip on
// a machine without one. This is the proof the Windows wrapper is owed before an
// EXISTING seed may be wrapped on upgrade (TPMWrapExistingSeedEnv): wrap, close
// the key handle, reopen, open; open in a fresh process. Still owed beyond this
// file, on a Windows 11 machine with a TPM: open after a reboot, and as the
// service user. Until a run records both, the upgrade stays opt-in.

const tpmHelperEnv = "TPM_SEEDWRAP_HELPER"

func TestTPMSeedWrapHelperProcess(t *testing.T) {
	path := os.Getenv(tpmHelperEnv)
	if path == "" {
		t.Skip("helper for TestTPMWrappedSeedOpensInAFreshProcess")
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := newPlatformSeedWrapper().Unwrap(blob)
	if err != nil {
		t.Fatalf("a fresh process could not open the wrapped seed: %v", err)
	}
	if !bytes.Equal(got, testSeed()) {
		t.Fatal("a fresh process opened the wrapped seed to different bytes")
	}
}

func tpmOrSkip(t *testing.T) SeedWrapper {
	t.Helper()
	w := newPlatformSeedWrapper()
	if !w.Available() {
		t.Skip("no usable TPM on this machine")
	}
	return w
}

// Wrap, let the key handle go, and open again through a freshly opened handle.
func TestTPMWrappedSeedOpensAfterTheKeyHandleIsClosedAndReopened(t *testing.T) {
	w := tpmOrSkip(t)
	seed := testSeed()
	blob, err := w.Wrap(seed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, seed) {
		t.Fatal("the wrapped blob holds the seed")
	}
	// Open the persisted key by name and free it, twice: the key must still be
	// there after its handle is gone, and not be recreated under the same name.
	for i := 0; i < 2; i++ {
		provider, key, err := openSeedKey()
		if err != nil {
			t.Fatalf("reopen %d: %v", i, err)
		}
		procFreeObject.Call(uintptr(key))
		procFreeObject.Call(uintptr(provider))
	}
	got, err := w.Unwrap(blob)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("the seed did not open after the key handle was closed and reopened: %v", err)
	}
}

func TestTPMWrappedSeedOpensInAFreshProcess(t *testing.T) {
	w := tpmOrSkip(t)
	blob, err := w.Wrap(testSeed())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "blob")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestTPMSeedWrapHelperProcess$", "-test.v")
	cmd.Env = append(os.Environ(), tpmHelperEnv+"="+path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fresh process: %v\n%s", err, out)
	}
}

func TestTPMWrappedSeedRefusesTampering(t *testing.T) {
	w := tpmOrSkip(t)
	blob, err := w.Wrap(testSeed())
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), blob...)
	bad[len(bad)-1] ^= 0x01
	if got, err := w.Unwrap(bad); err == nil && bytes.Equal(got, testSeed()) {
		t.Fatal("an altered blob opened to the seed")
	}
}

// Concurrent first calls to Available must not race to create the key.
func TestTPMAvailableIsSafeUnderConcurrentFirstCalls(t *testing.T) {
	w := newPlatformSeedWrapper()
	results := make(chan bool, 16)
	for i := 0; i < 16; i++ {
		go func() { results <- w.Available() }()
	}
	first := <-results
	for i := 1; i < 16; i++ {
		if <-results != first {
			t.Fatal("concurrent first calls disagreed about whether the TPM key works")
		}
	}
}
