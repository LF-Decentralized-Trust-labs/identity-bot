//go:build darwin && cgo && sepblob && !ios

package secureenclave

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// These run a REAL Secure Enclave wrap and unwrap. They skip on a Mac with no
// enclave. Run: go test -tags sepblob -run SEP ./secureenclave (after
// scripts/build-sep-shim.sh).

const sepHelperEnv = "SEP_SEEDWRAP_HELPER"

// The helper half: runs in a child process and unwraps what the parent wrapped.
func TestSEPSeedWrapHelperProcess(t *testing.T) {
	path := os.Getenv(sepHelperEnv)
	if path == "" {
		t.Skip("helper for TestSEPWrappedSeedOpensInAFreshProcess")
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&sepSeedWrapper{}).Unwrap(blob)
	if err != nil {
		t.Fatalf("a fresh process could not open the wrapped seed: %v", err)
	}
	if !bytes.Equal(got, testSeed()) {
		t.Fatal("a fresh process opened the wrapped seed to different bytes")
	}
}

// Wrap in this process, unwrap in a new one: the blob carries everything the
// enclave needs, and holds no seed.
func TestSEPWrappedSeedOpensInAFreshProcess(t *testing.T) {
	w := &sepSeedWrapper{}
	if !w.Available() {
		t.Skip("no usable Secure Enclave on this Mac")
	}
	seed := testSeed()
	blob, err := w.Wrap(seed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, seed) || bytes.Contains(blob, seed[:16]) {
		t.Fatal("the wrapped blob holds the seed")
	}
	path := filepath.Join(t.TempDir(), "blob")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSEPSeedWrapHelperProcess$", "-test.v")
	cmd.Env = append(os.Environ(), sepHelperEnv+"="+path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fresh process: %v\n%s", err, out)
	}
}

// A flipped byte anywhere in the blob is refused, never opened to other bytes.
func TestSEPWrappedSeedRefusesTampering(t *testing.T) {
	w := &sepSeedWrapper{}
	if !w.Available() {
		t.Skip("no usable Secure Enclave on this Mac")
	}
	blob, err := w.Wrap(testSeed())
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, len(blob) / 2, len(blob) - 1} {
		bad := append([]byte(nil), blob...)
		bad[i] ^= 0x01
		if got, err := w.Unwrap(bad); err == nil {
			t.Fatalf("a blob altered at byte %d opened (%d bytes)", i, len(got))
		}
	}
}
