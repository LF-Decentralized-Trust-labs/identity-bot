package secureenclave

import (
	"bytes"
	"errors"
	"log"
	"os"
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

// An identity stored unwrapped before the rule stays readable in production,
// is reported as not protected with how it gets protected, refuses nothing it
// already holds, and is wrapped in place once the app supplies its key.
func TestAnExistingUnwrappedPhoneIdentityStaysReadableAndGetsWrappedWhenTheAppSuppliesTheKey(t *testing.T) {
	standAPhone(t, true) // the old app, as it was: stored while unwrapped was allowed
	dir := t.TempDir()
	if err := StoreIdentityRootSeed(dir, theSeed()); err != nil {
		t.Fatal(err)
	}

	isDevBuild = func() bool { return false } // the upgrade: a production build now
	before, _ := os.ReadFile(rootSeedPath(dir))

	// A phone holding its owner's seed is where it belongs: it must not be
	// called "a machine that may not hold one" (which is never re-wrapped).
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	rootIdentityMisplacedWarning = sync.Once{}
	got, err := LoadRootSeed(dir)
	if err != nil || !bytes.Equal(got, theSeed()) {
		t.Fatalf("an existing identity became unopenable in production: %v", err)
	}
	if strings.Contains(logged.String(), "MAY NOT HOLD ONE") {
		t.Fatalf("an existing phone identity was reported as misplaced: %s", logged.String())
	}
	if after, _ := os.ReadFile(rootSeedPath(dir)); !bytes.Equal(before, after) {
		t.Fatal("the stored seed was rewritten with no key to wrap it under")
	}
	st := ReportSeedProtection(dir)
	if !st.Stored || st.HardwareProtected || st.Protection != ProtectionUnwrapped ||
		st.NotProtectedWhy == "" || st.HowItGetsProtected == "" || st.DevelopmentBuild {
		t.Fatalf("existing identity not reported as unprotected: %+v", st)
	}
	// ...while a NEW identity is still refused in this production build.
	if err := StoreIdentityRootSeed(t.TempDir(), theSeed()); !IsRootSeedRefusal(err) {
		t.Fatalf("a new identity was admitted: %v", err)
	}

	// The app now supplies its key: the next open wraps the seed.
	r := UseSeedWrapper(fakeWrap{works: true})
	defer r()
	got, err = LoadRootSeed(dir)
	if err != nil || !bytes.Equal(got, theSeed()) {
		t.Fatalf("open after the key arrived: %v", err)
	}
	if w := envelopeWrap(t, dir); w != "fake" {
		t.Fatalf("seed not wrapped once the key was supplied (wrap=%q)", w)
	}
	if st := ReportSeedProtection(dir); !st.HardwareProtected || st.NotProtectedWhy != "" {
		t.Fatalf("state after wrapping %+v", st)
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

// A development build, and every machine that is not a phone, still may keep a
// device-local seed unwrapped.
func TestDevelopmentAndNonPhonesMayStillKeepTheirOwnSeedUnwrapped(t *testing.T) {
	standAPhone(t, true)
	if _, err := EnsureRootSeed(t.TempDir()); err != nil {
		t.Fatalf("development build: %v", err)
	}
	standAPhone(t, false)
	thisIsAPhone = func() bool { return false }
	if _, err := EnsureRootSeed(t.TempDir()); err != nil {
		t.Fatalf("not a phone: %v", err)
	}
}
