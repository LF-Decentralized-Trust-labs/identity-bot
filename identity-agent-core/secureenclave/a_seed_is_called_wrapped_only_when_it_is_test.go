package secureenclave

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// theAppsKeystore stands the app's Keystore key: an RSA key the test holds, whose
// attestation chain is built by builtChain (a root the test pins in place of
// Google's), and which decrypts the way the hardware would.
type theAppsKeystore struct {
	works       bool
	chain       []byte
	decryptWith *rsa.PrivateKey
}

func (h *theAppsKeystore) Available() bool          { return h.works }
func (h *theAppsKeystore) AttestationChain() []byte { return h.chain }
func (h *theAppsKeystore) UnwrapKey(w []byte) ([]byte, error) {
	return oaepDecryptSHA256MGF1SHA1(h.decryptWith, w)
}

// theApp registers an app whose key is attested as spec says, and makes the test
// trust the test root in place of Google's.
func theApp(t *testing.T, spec chainSpec, works bool) *theAppsKeystore {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	spec.leafKey = &k.PublicKey
	chain, root := builtChain(t, spec)
	pinned := attestationRoots
	attestationRoots = [][sha256.Size]byte{root}
	h := &theAppsKeystore{works: works, chain: chain, decryptWith: k}
	DeclareSeedWrapHost(h)
	t.Cleanup(func() { DeclareSeedWrapHost(nil); attestationRoots = pinned })
	// The app declares who it is, and Google's list is a clean one unless a test
	// puts something on it.
	if err := DeclareAppIdentity(testAppPackage, [][]byte{testAppDigest}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ClearAppIdentity)
	googleStatusListIs(t, statusListJSON())
	return h
}

func aKeyIn(level int) chainSpec {
	return chainSpec{level: level, challenge: SeedWrapAttestationChallenge, purposes: []int{kmPurposeDecrypt},
		noAuth: true, created: time.Now().Add(-time.Hour),
		appPackage: testAppPackage, appDigests: [][]byte{testAppDigest}}
}

func usablePhone(t *testing.T, c Capability) {
	t.Helper()
	r := UseCapabilityDetector(func() Capability { return c })
	t.Cleanup(r)
}

// The app's key protects the seed, the envelope says which hardware as the
// attestation says it, and the file holds no seed. This is the round trip: the
// core encrypts to the attested key, the "hardware" decrypts.
func TestAnAppsKeystoreWrapperProtectsTheSeed(t *testing.T) {
	for level, scheme := range map[int]string{
		attestStrongBox:          "android-keystore-strongbox-rsa2048oaep-aes256gcm",
		attestTrustedEnvironment: "android-keystore-tee-rsa2048oaep-aes256gcm",
	} {
		t.Run(scheme, func(t *testing.T) {
			usablePhone(t, Capability{Status: Usable, Kind: "android_strongbox"})
			theApp(t, aKeyIn(level), true)
			r := UseSeedWrapper(declaredHostSeedWrapper())
			defer r()

			dir := t.TempDir()
			if err := StoreDeviceLocalSeed(dir, theSeed()); err != nil {
				t.Fatal(err)
			}
			p, got, _, err := RootSeedProtection(dir)
			if err != nil || p != ProtectionHardwareWrapped || got != scheme {
				t.Fatalf("envelope says %q/%q (%v)", p, got, err)
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
		})
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
			theApp(t, aKeyIn(attestTrustedEnvironment), true)
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

// THE POINT OF THE CHECK: an app cannot simply declare StrongBox. Every way it
// could try to makes the wrapper unavailable, and nothing is written.
func TestAnAppCannotDeclareHardwareItsKeyDoesNotProve(t *testing.T) {
	usablePhone(t, Capability{Status: Usable, Kind: "android_strongbox"})
	for name, c := range map[string]struct {
		spec  func() chainSpec
		chain func(h *theAppsKeystore) []byte
		why   string
	}{
		"no attestation at all": {spec: func() chainSpec { return aKeyIn(attestStrongBox) },
			chain: func(*theAppsKeystore) []byte { return nil }, why: "no attestation chain"},
		"a key held in software": {spec: func() chainSpec { return aKeyIn(attestSoftware) }, why: "software"},
		"a chain for another purpose": {spec: func() chainSpec {
			s := aKeyIn(attestStrongBox)
			s.challenge = "challenge"
			return s
		}, why: "challenge"},
		"an imported key": {spec: func() chainSpec {
			s := aKeyIn(attestStrongBox)
			s.imported = true
			return s
		}, why: "imported"},
		"a key that needs a person": {spec: func() chainSpec {
			s := aKeyIn(attestStrongBox)
			s.noAuth = false
			return s
		}, why: "authenticate"},
		"a chain nobody trusts": {spec: func() chainSpec { return aKeyIn(attestStrongBox) },
			chain: func(h *theAppsKeystore) []byte {
				other, _ := builtChain(t, chainSpec{level: attestStrongBox, challenge: SeedWrapAttestationChallenge,
					purposes: []int{kmPurposeDecrypt}, noAuth: true, created: time.Now().Add(-time.Hour), leafKey: &h.decryptWith.PublicKey})
				return other
			}, why: "Google attestation root"},
	} {
		t.Run(name, func(t *testing.T) {
			h := theApp(t, c.spec(), true)
			if c.chain != nil {
				h.chain = c.chain(h)
			}
			w := declaredHostSeedWrapper()
			if w.Available() {
				t.Fatal("an unproven key was available")
			}
			if _, err := w.Wrap(theSeed()); err == nil {
				t.Fatal("wrapped under a key that proves nothing")
			}
			if why := whyNotWrapped(); !strings.Contains(why, c.why) {
				// whyNotWrapped goes through platformSeedWrapper.
				r := UseSeedWrapper(w)
				why = whyNotWrapped()
				r()
				if !strings.Contains(why, c.why) {
					t.Fatalf("the refusal does not say why (%q)", why)
				}
			}
			r := UseSeedWrapper(w)
			defer r()
			dir := t.TempDir()
			if err := StoreDeviceLocalSeed(dir, theSeed()); err == nil {
				if p, _, _, _ := RootSeedProtection(dir); p == ProtectionHardwareWrapped {
					t.Fatal("recorded as hardware-wrapped")
				}
			}
		})
	}
}

// An app that attests a REAL hardware key and then decrypts with a different,
// software one: the core encrypted to the attested key, so the software key
// cannot open it and the store is refused with nothing written.
func TestAnAppThatAttestsOneKeyAndHoldsAnotherStoresNothing(t *testing.T) {
	usablePhone(t, Capability{Status: Usable, Kind: "android_strongbox"})
	h := theApp(t, aKeyIn(attestStrongBox), true)
	h.decryptWith = softwareRSA(t)
	r := UseSeedWrapper(declaredHostSeedWrapper())
	defer r()
	dir := t.TempDir()
	if err := StoreDeviceLocalSeed(dir, theSeed()); err == nil {
		t.Fatal("stored")
	}
	if _, err := os.Stat(rootSeedPath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a seed file exists after the refusal")
	}
}

// A seed written under a checked key stays readable when the attestation can no
// longer be checked (Google reissues its roots, the chain's certificates expire).
func TestAStoredSeedStaysReadableWhenTheChainCanNoLongerBeChecked(t *testing.T) {
	usablePhone(t, Capability{Status: Usable, Kind: "android_strongbox"})
	theApp(t, aKeyIn(attestStrongBox), true)
	r := UseSeedWrapper(declaredHostSeedWrapper())
	defer r()
	dir := t.TempDir()
	if err := StoreDeviceLocalSeed(dir, theSeed()); err != nil {
		t.Fatal(err)
	}
	attestationRoots = nil // the build no longer trusts what signed the chain
	if declaredHostSeedWrapper().Available() {
		t.Fatal("still available")
	}
	if got, err := LoadRootSeed(dir); err != nil || !bytes.Equal(got, theSeed()) {
		t.Fatalf("the seed became unreadable: %v", err)
	}
}

// A blob the hardware did not make, or one that was altered, is not opened.
func TestAHostWrapBlobThatWasTamperedWithIsNotOpened(t *testing.T) {
	usablePhone(t, Capability{Status: Usable, Kind: "android_strongbox"})
	theApp(t, aKeyIn(attestTrustedEnvironment), true)
	w := declaredHostSeedWrapper()
	blob, err := w.Wrap(theSeed())
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []int{0, 1, 3, 40, len(blob) - 1} {
		bad := bytes.Clone(blob)
		bad[at] ^= 1
		if got, err := w.Unwrap(bad); err == nil && bytes.Equal(got, theSeed()) {
			t.Fatalf("a blob altered at byte %d still opened", at)
		}
	}
	for _, b := range [][]byte{nil, {1}, {1, 0xff, 0xff}, blob[:10]} {
		if _, err := w.Unwrap(b); err == nil {
			t.Fatalf("opened %d bytes", len(b))
		}
	}
	if a, b := mustWrap(t, w), mustWrap(t, w); bytes.Equal(a, b) {
		t.Fatal("two wraps of one seed were identical")
	}
}

func mustWrap(t *testing.T, w SeedWrapper) []byte {
	t.Helper()
	b, err := w.Wrap(theSeed())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A wrapper that works but whose key cannot be used right now is not available.
func TestAnAppWrapperThatSaysItCannotWorkIsNotAvailable(t *testing.T) {
	usablePhone(t, Capability{Status: Usable, Kind: KindAndroidTEE})
	theApp(t, aKeyIn(attestTrustedEnvironment), false)
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

// A seed stays readable when the app can no longer hand over its chain at all
// (a failed Keystore call, a changed key's metadata) and in a new process, where
// nothing has been verified yet. The label names the level that was verified.
func TestAStoredSeedOpensWhenTheChainCannotBeReadAtAll(t *testing.T) {
	usablePhone(t, Capability{Status: Usable, Kind: "android_strongbox"})
	h := theApp(t, aKeyIn(attestStrongBox), true)
	r := UseSeedWrapper(declaredHostSeedWrapper())
	defer r()
	dir := t.TempDir()
	if err := StoreDeviceLocalSeed(dir, theSeed()); err != nil {
		t.Fatal(err)
	}
	h.chain = nil
	DeclareSeedWrapHost(h) // a new process: nothing verified yet
	if got, err := LoadRootSeed(dir); err != nil || !bytes.Equal(got, theSeed()) {
		t.Fatalf("the seed became unreadable: %v", err)
	}
}

// The label is the level the CHECK found, not whatever the app's chain says by
// the time the label is read.
func TestTheStoredSchemeIsTheVerifiedLevelNotASecondReading(t *testing.T) {
	usablePhone(t, Capability{Status: Usable, Kind: KindAndroidTEE})
	h := theApp(t, aKeyIn(attestTrustedEnvironment), true)
	w := declaredHostSeedWrapper()
	if _, err := w.Wrap(theSeed()); err != nil {
		t.Fatal(err)
	}
	// The app now offers a chain that claims StrongBox.
	lie := aKeyIn(attestStrongBox)
	lie.leafKey = &h.decryptWith.PublicKey
	other, _ := builtChain(t, lie)
	h.chain = other
	if got := w.Scheme(); got != "android-keystore-tee-rsa2048oaep-aes256gcm" {
		t.Fatalf("the label followed the app's second chain: %s", got)
	}
}
