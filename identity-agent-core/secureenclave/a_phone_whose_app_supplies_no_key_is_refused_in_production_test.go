package secureenclave

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Owner's decision, 2026-11-05: an Android PRODUCTION build must not found or
// recover an identity whose root seed is not wrapped by StrongBox or TEE
// hardware. A DEVELOPMENT build may, and says plainly that the seed is not
// hardware-protected. There is no exemption for an old app that registers no
// wrapper.

// standAPhone stands an Android phone with a usable TEE Keystore, no seed
// wrapper registered by its app, in a production or development build.
func standAPhone(t *testing.T, dev bool) {
	t.Helper()
	r1 := UseCapabilityDetector(func() Capability { return Capability{Status: Usable, Kind: KindAndroidTEE} })
	r2 := UseSeedWrapper(nil)
	r3 := UseFoundingVerdict(func() FoundingVerdict { return FoundingVerdict{Permitted: true, Platform: "android"} })
	pd, pp := isDevBuild, thisIsAPhone
	isDevBuild = func() bool { return dev }
	thisIsAPhone = func() bool { return true }
	t.Cleanup(func() { isDevBuild, thisIsAPhone = pd, pp; r3(); r2(); r1() })
}

func TestProductionRefusesAPhoneWhoseAppSuppliesNoSeedKey(t *testing.T) {
	standAPhone(t, false)
	dir := t.TempDir()

	for name, f := range map[string]func() error{
		"check": func() error { return CheckRootSeedMayLiveHere(dir) },
		"store": func() error { return StoreIdentityRootSeed(dir, theSeed()) },
	} {
		err := f()
		var refusal *ErrRootSeedCannotLiveHere
		if !errors.As(err, &refusal) || !refusal.Phone {
			t.Fatalf("%s: want a phone's refusal, got %v", name, err)
		}
		if refusal.UserMessage() != "this phone's secure hardware is not available to this app yet" ||
			!strings.HasPrefix(err.Error(), refusal.UserMessage()) {
			t.Fatalf("%s: the app is not given the plain reason: %q", name, err)
		}
	}
	if _, serr := os.Stat(rootSeedPath(dir)); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("a seed file exists after the refusal: %v", serr)
	}
	ok, why := RootKeyPermittedHere(dir)
	if ok || why != PhoneHardwareUnavailable {
		t.Fatalf("RootKeyPermittedHere = %v, %q; want false with the same reason", ok, why)
	}
}

// An app that did register a wrapper, but whose key does not work, is refused
// the same way (it never had an exemption).
func TestProductionRefusesAPhoneWhoseSeedKeyDoesNotWork(t *testing.T) {
	standAPhone(t, false)
	r := UseSeedWrapper(fakeWrap{works: false})
	defer r()
	if err := StoreIdentityRootSeed(t.TempDir(), theSeed()); !IsRootSeedRefusal(err) {
		t.Fatalf("want refusal, got %v", err)
	}
}

// A phone whose app supplies a working key is not refused, and the seed is
// hardware-wrapped and reported as protected.
func TestProductionAcceptsAPhoneWhoseAppSuppliesItsKey(t *testing.T) {
	standAPhone(t, false)
	r := UseSeedWrapper(fakeWrap{works: true})
	defer r()
	dir := t.TempDir()
	if err := StoreIdentityRootSeed(dir, theSeed()); err != nil {
		t.Fatal(err)
	}
	st := ReportSeedProtection(dir)
	if !st.HardwareProtected || st.Protection != ProtectionHardwareWrapped || st.NotProtectedWhy != "" {
		t.Fatalf("state %+v", st)
	}
	if ok, _ := RootKeyPermittedHere(dir); !ok {
		t.Fatal("not permitted though wrapped")
	}
}

func TestDevelopmentAllowsAPhoneWithNoSeedKeyAndFlagsItWhereTheAppReadsIt(t *testing.T) {
	standAPhone(t, true)
	dir := t.TempDir()

	// Before anything is stored the state already says it would not be protected.
	if st := ReportSeedProtection(dir); st.HardwareProtected || st.NotProtectedWhy == "" || !st.DevelopmentBuild {
		t.Fatalf("pre-store state %+v", st)
	}
	if err := StoreIdentityRootSeed(dir, theSeed()); err != nil {
		t.Fatalf("a development build was refused: %v", err)
	}
	p, scheme, why, err := RootSeedProtection(dir)
	if err != nil || p != ProtectionUnwrapped || scheme != seedWrapNone || !strings.Contains(why, "StrongBox") {
		t.Fatalf("envelope says %q/%q/%q (%v)", p, scheme, why, err)
	}
	st := ReportSeedProtection(dir)
	if !st.Stored || st.HardwareProtected || st.Protection != ProtectionUnwrapped ||
		!strings.Contains(st.NotProtectedWhy, "StrongBox") || !st.DevelopmentBuild {
		t.Fatalf("state the apps read presents the seed as protected or silent: %+v", st)
	}
	if got, err := LoadRootSeed(dir); err != nil || !bytes.Equal(got, theSeed()) {
		t.Fatalf("round trip: %v", err)
	}
}

// An identity stored unwrapped before the rule is NOT served by a production
// build (owner's rule, 2026-11-05: block any production running without
// hardware protection). Every use of it gets the root-seed refusal, the stored
// file is left alone, it is reported as not protected with how it gets
// protected, and once the app supplies its key the core wraps it in place and
// it works again. The old behaviour (stays readable, pairwise mints, the machine
// owner and adopt keep working on it) is what this replaces.
func TestAnExistingUnwrappedPhoneIdentityIsRefusedInProductionUntilItIsWrapped(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "envelope"
		if legacy {
			name = "legacy file"
		}
		t.Run(name, func(t *testing.T) {
			standAPhone(t, true) // the old app, as it was: stored while unwrapped was allowed
			dir := t.TempDir()
			if legacy {
				if err := os.MkdirAll(filepath.Dir(rootSeedPath(dir)), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(rootSeedPath(dir), theSeed(), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := StoreIdentityRootSeed(dir, theSeed()); err != nil {
				t.Fatal(err)
			}

			// A development build keeps serving it, flagged as not protected.
			if got, err := LoadRootSeed(dir); err != nil || !bytes.Equal(got, theSeed()) {
				t.Fatalf("a development build could not read it: %v", err)
			}
			if st := ReportSeedProtection(dir); st.HardwareProtected || !st.DevelopmentBuild {
				t.Fatalf("development state %+v", st)
			}

			isDevBuild = func() bool { return false } // the upgrade: a production build now
			before, _ := os.ReadFile(rootSeedPath(dir))

			var logged bytes.Buffer
			log.SetOutput(&logged)
			defer log.SetOutput(os.Stderr)
			rootIdentityMisplacedWarning = sync.Once{}
			// Every way of using the seed is refused, and none returns it.
			if got, err := LoadRootSeed(dir); !IsRootSeedRefusal(err) || got != nil {
				t.Fatalf("a production build served an unwrapped seed: %v", err)
			}
			if _, err := EnsureRootSeed(dir); !IsRootSeedRefusal(err) {
				t.Fatalf("EnsureRootSeed served it: %v", err)
			}
			if err := ProtectExistingSeed(dir); !IsRootSeedRefusal(err) {
				t.Fatalf("launch did not report the refusal: %v", err)
			}
			if strings.Contains(logged.String(), "MAY NOT HOLD ONE") {
				t.Fatalf("a phone identity was reported as misplaced: %s", logged.String())
			}
			if after, _ := os.ReadFile(rootSeedPath(dir)); !bytes.Equal(before, after) {
				t.Fatal("the stored seed was rewritten with no key to wrap it under")
			}
			st := ReportSeedProtection(dir)
			if !st.Stored || st.HardwareProtected || st.Protection == ProtectionHardwareWrapped ||
				st.NotProtectedWhy == "" || st.HowItGetsProtected == "" || st.DevelopmentBuild {
				t.Fatalf("existing identity not reported as unprotected: %+v", st)
			}
			// ...and a NEW identity is refused in this production build too.
			if err := StoreIdentityRootSeed(t.TempDir(), theSeed()); !IsRootSeedRefusal(err) {
				t.Fatalf("a new identity was admitted: %v", err)
			}

			// The app now supplies its key: launch wraps the seed, and it works.
			r := UseSeedWrapper(fakeWrap{works: true})
			defer r()
			if err := ProtectExistingSeed(dir); err != nil {
				t.Fatalf("launch with the key: %v", err)
			}
			if w := envelopeWrap(t, dir); w != "fake" {
				t.Fatalf("seed not wrapped once the key was supplied (wrap=%q)", w)
			}
			if got, err := LoadRootSeed(dir); err != nil || !bytes.Equal(got, theSeed()) {
				t.Fatalf("open after wrapping: %v", err)
			}
			if st := ReportSeedProtection(dir); !st.HardwareProtected || st.NotProtectedWhy != "" {
				t.Fatalf("state after wrapping %+v", st)
			}
		})
	}
}

// EnsureRootSeed makes the machine's own seed, which on a phone in a production
// build must be wrapped as well: a phone paired to an identity kept elsewhere
// still has one (owner's rule, 2026-11-05). Nothing is written without a wrapper.
func TestProductionRefusesAPhonesOwnSeedUnwrapped(t *testing.T) {
	standAPhone(t, false)
	dir := t.TempDir()
	_, err := EnsureRootSeed(dir)
	if !IsRootSeedRefusal(err) {
		t.Fatalf("want a refusal, got %v", err)
	}
	if _, serr := os.Stat(rootSeedPath(dir)); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("a seed file exists after the refusal: %v", serr)
	}
	if err := StoreDeviceLocalSeed(dir, theSeed()); !IsRootSeedRefusal(err) {
		t.Fatalf("StoreDeviceLocalSeed: want a refusal, got %v", err)
	}

	// With a working wrapper the phone's own seed is made, wrapped.
	r := UseSeedWrapper(fakeWrap{works: true})
	defer r()
	if _, err := EnsureRootSeed(dir); err != nil {
		t.Fatal(err)
	}
	if p, _, _, _ := RootSeedProtection(dir); p != ProtectionHardwareWrapped {
		t.Fatalf("protection %q, want hardware-wrapped", p)
	}
}

// A development build may keep a device-local seed unwrapped; a production
// build on any platform may not (owner's rule, 2026-11-05), whether or not it is
// a phone: a Windows machine with no TPM and a macOS build without the Secure
// Enclave wrapper have no wrapper, and so write nothing.
func TestOnlyADevelopmentBuildMayKeepItsOwnSeedUnwrapped(t *testing.T) {
	standAPhone(t, true)
	if _, err := EnsureRootSeed(t.TempDir()); err != nil {
		t.Fatalf("development build: %v", err)
	}
	standAPhone(t, false)
	thisIsAPhone = func() bool { return false }
	dir := t.TempDir()
	if _, err := EnsureRootSeed(dir); !IsRootSeedRefusal(err) {
		t.Fatalf("a production machine with no wrapper stored its own seed: %v", err)
	}
	if err := StoreDeviceLocalSeed(dir, theSeed()); !IsRootSeedRefusal(err) {
		t.Fatalf("StoreDeviceLocalSeed: want a refusal, got %v", err)
	}
	if _, serr := os.Stat(rootSeedPath(dir)); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("a seed file exists after the refusal: %v", serr)
	}
	r := UseSeedWrapper(fakeWrap{works: true})
	defer r()
	if _, err := EnsureRootSeed(dir); err != nil {
		t.Fatalf("with a working wrapper: %v", err)
	}
}
