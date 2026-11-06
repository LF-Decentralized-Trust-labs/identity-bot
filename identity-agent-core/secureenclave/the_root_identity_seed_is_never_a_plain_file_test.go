package secureenclave

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

type fakeWrap struct{ works bool }

func (f fakeWrap) Available() bool               { return f.works }
func (fakeWrap) Scheme() string                  { return "fake" }
func (fakeWrap) Wrap(p []byte) ([]byte, error)   { return xorFake(p), nil }
func (fakeWrap) Unwrap(b []byte) ([]byte, error) { return xorFake(b), nil }

func machine(t *testing.T, c Capability, wrapperWorks bool) {
	t.Helper()
	r1 := UseCapabilityDetector(func() Capability { return c })
	r2 := UseSeedWrapper(fakeWrap{wrapperWorks})
	t.Cleanup(func() { r2(); r1() })
}

func theSeed() []byte { return bytes.Repeat([]byte{9}, 64) }

func TestRootSeedMayLiveHereCombinations(t *testing.T) {
	usable := Capability{Status: Usable}
	for _, c := range []struct {
		name    string
		cap     Capability
		wrapper bool
		dev     bool
		want    bool
	}{
		{"usable and wrapped", usable, true, false, true},
		{"usable but no wrapper", usable, false, false, false},
		{"absent", Capability{Status: Absent}, true, false, false},
		{"unknown", Capability{Status: Unknown}, true, false, false},
		{"zero value", Capability{}, true, false, false},
		{"development build, nothing works", Capability{}, false, true, true},
	} {
		if got := rootSeedMayLiveHere(c.cap, c.wrapper, c.dev); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestIdentityRootSeedNeverReachesThePlaintextEnvelope(t *testing.T) {
	for name, m := range map[string]struct {
		cap     Capability
		wrapper bool
	}{
		"no hardware":              {Capability{Status: Absent}, false},
		"hardware, wrapper broken": {Capability{Status: Usable}, false},
		"unknown, wrapper works":   {Capability{Status: Unknown}, true},
	} {
		t.Run(name, func(t *testing.T) {
			machine(t, m.cap, m.wrapper)
			dir := t.TempDir()
			err := StoreIdentityRootSeed(dir, theSeed())
			if !IsRootSeedRefusal(err) {
				t.Fatalf("want refusal, got %v", err)
			}
			if _, serr := os.Stat(rootSeedPath(dir)); !errors.Is(serr, os.ErrNotExist) {
				t.Fatalf("a seed file exists after a refusal: %v", serr)
			}
		})
	}
	// The storer itself, bypassing the capability question entirely: asked to
	// require a wrap with none available it must still write nothing.
	dir := t.TempDir()
	if err := storeSeed(dir, theSeed(), nil, true); !IsRootSeedRefusal(err) {
		t.Fatalf("storeSeed(requireWrap) without a wrapper: %v", err)
	}
	if _, serr := os.Stat(rootSeedPath(dir)); !errors.Is(serr, os.ErrNotExist) {
		t.Fatal("storeSeed(requireWrap) wrote a plaintext file")
	}
}

func TestIdentityRootSeedIsStoredWrappedWhereTheMachineCan(t *testing.T) {
	machine(t, Capability{Status: Usable, Kind: KindTPM2}, true)
	dir := t.TempDir()
	if err := StoreIdentityRootSeed(dir, theSeed()); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(rootSeedPath(dir))
	if !bytes.Contains(raw, []byte(`"wrap":"fake"`)) {
		t.Fatalf("not wrapped: %s", raw)
	}
	if got, err := LoadRootSeed(dir); err != nil || !bytes.Equal(got, theSeed()) {
		t.Fatalf("round trip: %v", err)
	}
}

// The machine's own seed is not a person's identity and is still allowed to be
// stored where nothing can wrap it — the distinction the two names exist for.
func TestDeviceLocalSeedMayStillBeStoredUnwrapped(t *testing.T) {
	machine(t, Capability{Status: Absent}, false)
	dir := t.TempDir()
	if _, err := EnsureRootSeed(dir); err != nil {
		t.Fatalf("a device-local seed must not be refused: %v", err)
	}
}

// xorFake is a stand-in that really changes the bytes, so a test seed is never
// sitting in the clear inside its own "wrapped" form.
func xorFake(p []byte) []byte {
	out := make([]byte, len(p))
	for i, b := range p {
		out[i] = b ^ 0xA5
	}
	return out
}
