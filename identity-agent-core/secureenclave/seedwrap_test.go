package secureenclave

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// fakeWrapper stands in for a hardware element: AES-GCM under a key the test
// holds, so wrap/unwrap semantics (including "wrong device" failures) are real.
type fakeWrapper struct {
	key       []byte
	available bool
	scheme    string
}

func (f *fakeWrapper) Available() bool { return f.available }
func (f *fakeWrapper) Scheme() string {
	if f.scheme != "" {
		return f.scheme
	}
	return "fake-hw"
}
func (f *fakeWrapper) Wrap(plain []byte) ([]byte, error) {
	block, _ := aes.NewCipher(f.key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, gcm.Seal(nil, nonce, plain, nil)...), nil
}
func (f *fakeWrapper) Unwrap(blob []byte) ([]byte, error) {
	block, _ := aes.NewCipher(f.key)
	gcm, _ := cipher.NewGCM(block)
	if len(blob) < gcm.NonceSize() {
		return nil, fmt.Errorf("short blob")
	}
	return gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], nil)
}

func withWrapper(t *testing.T, w SeedWrapper) {
	t.Helper()
	orig := platformSeedWrapper
	platformSeedWrapper = func() SeedWrapper { return w }
	t.Cleanup(func() { platformSeedWrapper = orig })
}

func testSeed() []byte {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return seed
}

// Without a hardware wrapper, the seed round-trips through the envelope form.
func TestSeedEnvelopeRoundTripNoWrapper(t *testing.T) {
	withWrapper(t, nil)
	dir := t.TempDir()
	seed := testSeed()
	if err := StoreRootSeed(dir, seed); err != nil {
		t.Fatalf("store: %v", err)
	}
	got, err := LoadRootSeed(dir)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("load: %v", err)
	}
	raw, _ := os.ReadFile(rootSeedPath(dir))
	var env seedEnvelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Wrap != seedWrapNone {
		t.Fatalf("expected none-wrapped envelope, got %s", raw)
	}
}

// With a wrapper, the file holds ciphertext only and loads back through unwrap.
func TestSeedWrappedRoundTrip(t *testing.T) {
	fw := &fakeWrapper{key: bytes.Repeat([]byte{7}, 32), available: true}
	withWrapper(t, fw)
	dir := t.TempDir()
	seed := testSeed()
	if err := StoreRootSeed(dir, seed); err != nil {
		t.Fatalf("store: %v", err)
	}
	raw, _ := os.ReadFile(rootSeedPath(dir))
	if bytes.Contains(raw, seed[:16]) {
		t.Fatal("seed bytes must not appear in the wrapped file")
	}
	var env seedEnvelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Wrap != "fake-hw" {
		t.Fatalf("expected fake-hw envelope, got %s", raw)
	}
	got, err := LoadRootSeed(dir)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("load: %v", err)
	}
}

// A legacy raw-bytes seed file loads correctly and migrates to the (wrapped)
// envelope on first read.
func TestLegacySeedFileMigrates(t *testing.T) {
	fw := &fakeWrapper{key: bytes.Repeat([]byte{9}, 32), available: true}
	withWrapper(t, fw)
	dir := t.TempDir()
	seed := testSeed()
	p := rootSeedPath(dir)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, seed, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadRootSeed(dir)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("legacy load: %v", err)
	}
	raw, _ := os.ReadFile(p)
	var env seedEnvelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Wrap != "fake-hw" {
		t.Fatalf("legacy file must migrate to wrapped envelope, got %s", raw)
	}
	got2, err := LoadRootSeed(dir)
	if err != nil || !bytes.Equal(got2, seed) {
		t.Fatalf("post-migration load: %v", err)
	}
}

// A seed stored unwrapped upgrades to wrapped when hardware becomes usable.
func TestSeedUpgradesWhenWrapperAppears(t *testing.T) {
	withWrapper(t, nil)
	dir := t.TempDir()
	seed := testSeed()
	if err := StoreRootSeed(dir, seed); err != nil {
		t.Fatal(err)
	}

	fw := &fakeWrapper{key: bytes.Repeat([]byte{3}, 32), available: true}
	withWrapper(t, fw)
	got, err := LoadRootSeed(dir)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("load during upgrade: %v", err)
	}
	raw, _ := os.ReadFile(rootSeedPath(dir))
	var env seedEnvelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Wrap != "fake-hw" {
		t.Fatalf("expected upgraded envelope, got %s", raw)
	}
}

// A wrapped seed fails closed with an actionable error when the platform cannot
// open it (moved to another device / hardware key gone / wrong key).
func TestWrappedSeedFailsClosed(t *testing.T) {
	fw := &fakeWrapper{key: bytes.Repeat([]byte{5}, 32), available: true}
	withWrapper(t, fw)
	dir := t.TempDir()
	if err := StoreRootSeed(dir, testSeed()); err != nil {
		t.Fatal(err)
	}

	// No wrapper at all (file copied to a platform without hardware).
	withWrapper(t, nil)
	if _, err := LoadRootSeed(dir); err == nil {
		t.Fatal("must fail when no wrapper can open the seed")
	}

	// Wrong hardware key (a different device's element).
	withWrapper(t, &fakeWrapper{key: bytes.Repeat([]byte{6}, 32), available: true})
	if _, err := LoadRootSeed(dir); err == nil {
		t.Fatal("must fail with a different device key")
	}
}

// A wrapper that cannot verify its own round trip must abort the store, leaving
// no file behind rather than an unopenable one.
func TestStoreRejectsUnverifiableWrap(t *testing.T) {
	bad := &badWrapper{}
	withWrapper(t, bad)
	dir := t.TempDir()
	if err := StoreRootSeed(dir, testSeed()); err == nil {
		t.Fatal("store must fail when the wrap round trip fails")
	}
	if _, err := os.Stat(rootSeedPath(dir)); !os.IsNotExist(err) {
		t.Fatal("no seed file may be written on a failed wrap")
	}
}

type badWrapper struct{}

func (badWrapper) Available() bool               { return true }
func (badWrapper) Scheme() string                { return "bad" }
func (badWrapper) Wrap(p []byte) ([]byte, error) { return []byte("garbage"), nil }
func (badWrapper) Unwrap([]byte) ([]byte, error) { return nil, fmt.Errorf("nope") }

func TestStoreRejectsShortSeed(t *testing.T) {
	withWrapper(t, nil)
	if err := StoreRootSeed(t.TempDir(), []byte("short")); err == nil {
		t.Fatal("short seed must be rejected")
	}
}
