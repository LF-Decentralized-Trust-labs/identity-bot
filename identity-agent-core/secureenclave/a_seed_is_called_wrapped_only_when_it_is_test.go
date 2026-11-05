package secureenclave

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// hostFor stands the app's Keystore wrapper: a real AES-GCM wrap under a key the
// test holds, which is what a Keystore key does from the core's side.
type hostFor struct {
	*fakeWrapper
	scheme string
}

func (h hostFor) Scheme() string { return h.scheme }

func theApp(t *testing.T, scheme string, works bool) {
	t.Helper()
	DeclareSeedWrapHost(hostFor{&fakeWrapper{key: bytes.Repeat([]byte{7}, 32), available: works}, scheme})
	t.Cleanup(func() { DeclareSeedWrapHost(nil) })
}

func usablePhone(t *testing.T, c Capability) {
	t.Helper()
	r := UseCapabilityDetector(func() Capability { return c })
	t.Cleanup(r)
}

// The app's wrapper is used, the envelope says hardware-wrapped under the app's
// scheme, and the file holds no seed.
func TestAnAppsKeystoreWrapperProtectsTheSeed(t *testing.T) {
	usablePhone(t, Capability{Status: Usable, Kind: "android_strongbox"})
	theApp(t, "android-keystore-strongbox-aes256gcm", true)
	r := UseSeedWrapper(declaredHostSeedWrapper())
	defer r()

	dir := t.TempDir()
	if err := StoreDeviceLocalSeed(dir, theSeed()); err != nil {
		t.Fatal(err)
	}
	p, scheme, _, err := RootSeedProtection(dir)
	if err != nil || p != ProtectionHardwareWrapped || scheme != "android-keystore-strongbox-aes256gcm" {
		t.Fatalf("envelope says %q/%q (%v)", p, scheme, err)
	}
	raw, _ := os.ReadFile(rootSeedPath(dir))
	if bytes.Contains(raw, theSeed()) {
		t.Fatal("the wrapped seed file contains the seed")
	}
	if got, err := LoadRootSeed(dir); err != nil || !bytes.Equal(got, theSeed()) {
		t.Fatalf("round trip: %v", err)
	}
	if !SeedWrapAvailable() || SeedWrapScheme() != scheme {
		t.Fatalf("the route would report %v/%q", SeedWrapAvailable(), SeedWrapScheme())
	}
}

// The app cannot make a phone look hardware-protected: its wrapper counts only
// while the phone's key protection was proven usable.
func TestAnAppWrapperDoesNotCountWhereTheHardwareWasNotProven(t *testing.T) {
	for name, c := range map[string]Capability{
		"absent":  {Status: Absent, Reason: "no_keystore"},
		"unknown": Unproven("app_did_not_report_key_protection", ""),
		"present": {Status: Present, Kind: KindAndroidTEE},
	} {
		t.Run(name, func(t *testing.T) {
			usablePhone(t, c)
			theApp(t, "android-keystore-tee-aes256gcm", true)
			r := UseSeedWrapper(declaredHostSeedWrapper())
			defer r()
			if SeedWrapAvailable() || SeedWrapScheme() != "none" {
				t.Fatalf("a phone with %s hardware was reported wrapped (%q)", name, SeedWrapScheme())
			}
			dir := t.TempDir()
			if err := StoreIdentityRootSeed(dir, theSeed()); err == nil {
				if p, _, _, _ := RootSeedProtection(dir); p == ProtectionHardwareWrapped {
					t.Fatal("recorded as hardware-wrapped")
				}
			}
		})
	}
}

// A scheme that would make the envelope claim something the Keystore did not do.
func TestAnAppWrapperCannotNameItselfNoneOrTheSealedVolume(t *testing.T) {
	usablePhone(t, Capability{Status: Usable, Kind: KindAndroidTEE})
	for _, scheme := range []string{"", "none", SealedVolumeScheme} {
		theApp(t, scheme, true)
		if w := declaredHostSeedWrapper(); w.Available() {
			t.Fatalf("scheme %q accepted", scheme)
		}
	}
}

// A wrapper that works but whose key cannot be used right now is not available.
func TestAnAppWrapperThatSaysItCannotWorkIsNotAvailable(t *testing.T) {
	usablePhone(t, Capability{Status: Usable, Kind: KindAndroidTEE})
	theApp(t, "android-keystore-tee-aes256gcm", false)
	if declaredHostSeedWrapper().Available() {
		t.Fatal("available")
	}
}

// With no app wrapper there is nothing declared and the seam says nil.
func TestNoAppWrapperMeansNoWrapper(t *testing.T) {
	DeclareSeedWrapHost(nil)
	if declaredHostSeedWrapper() != nil {
		t.Fatal("a wrapper out of nowhere")
	}
}

// leaky is a wrapper that "wraps" by returning the seed inside its output.
type leaky struct{}

func (leaky) Available() bool                 { return true }
func (leaky) Scheme() string                  { return "leaky-hw" }
func (leaky) Wrap(p []byte) ([]byte, error)   { return append([]byte("hdr"), p...), nil }
func (leaky) Unwrap(b []byte) ([]byte, error) { return b[3:], nil }

type emptyWrap struct{ leaky }

func (emptyWrap) Wrap([]byte) ([]byte, error) { return nil, nil }

// A wrapper that hands the seed back in its output is never recorded as
// wrapping it, and nothing is written.
func TestAWrapperThatLeaksTheSeedIsNotRecordedAsWrapping(t *testing.T) {
	usablePhone(t, Capability{Status: Usable, Kind: KindTPM2})
	for name, w := range map[string]SeedWrapper{"leaky": leaky{}, "empty": emptyWrap{}} {
		t.Run(name, func(t *testing.T) {
			r := UseSeedWrapper(w)
			defer r()
			dir := t.TempDir()
			err := StoreDeviceLocalSeed(dir, theSeed())
			if err == nil {
				t.Fatal("stored")
			}
			if _, serr := os.Stat(rootSeedPath(dir)); !errors.Is(serr, os.ErrNotExist) {
				t.Fatal("a seed file exists after the refusal")
			}
		})
	}
}

// The sealed-volume scheme is the one wrapper that is the identity, on purpose.
func TestTheSealedVolumeIsNotMistakenForALeak(t *testing.T) {
	if wrapLeaksTheSeed(SealedVolumeSeedWrapper(), theSeed(), theSeed()) {
		t.Fatal("the sealed volume was refused for being what it is")
	}
	if !wrapLeaksTheSeed(&fakeWrapper{scheme: "anything-else"}, theSeed(), theSeed()) {
		t.Fatal("a leak was missed")
	}
	// Naming itself "sealed-volume" earns no exemption: only the type does.
	if !wrapLeaksTheSeed(&fakeWrapper{scheme: SealedVolumeScheme}, theSeed(), theSeed()) {
		t.Fatal("a wrapper that only claims the sealed-volume name was exempted from the leak check")
	}
}

// The TPM wrapped-seed frame is checked on every host; the Windows calls that
// fill it are not.
func TestTheTPMWrapFrameRoundTripsAndRefusesTheMalformed(t *testing.T) {
	ct := bytes.Repeat([]byte{9}, tpmWrapCipherLen)
	for _, h := range []byte{tpmWrapSHA256, tpmWrapSHA1} {
		blob, err := packTPMWrap(h, ct)
		if err != nil {
			t.Fatal(err)
		}
		gh, gct, err := unpackTPMWrap(blob)
		if err != nil || gh != h || !bytes.Equal(gct, ct) {
			t.Fatalf("hash %d: %v", h, err)
		}
	}
	if _, err := packTPMWrap(0, ct); err == nil {
		t.Error("unknown hash packed")
	}
	if _, err := packTPMWrap(tpmWrapSHA256, ct[:10]); err == nil {
		t.Error("short ciphertext packed")
	}
	good, _ := packTPMWrap(tpmWrapSHA256, ct)
	for name, b := range map[string][]byte{"short": good[:50], "long": append(good, 0), "badhash": append([]byte{9}, ct...)} {
		if _, _, err := unpackTPMWrap(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
