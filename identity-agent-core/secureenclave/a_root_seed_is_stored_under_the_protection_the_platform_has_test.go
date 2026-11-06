package secureenclave

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func asSealedHost(t *testing.T) {
	t.Helper()
	r1 := UseCapabilityDetector(func() Capability {
		return Capability{Status: Usable, Kind: KindSEVSNP}
	})
	r2 := UseSeedWrapper(SealedVolumeSeedWrapperOn(func() error { return nil }))
	t.Cleanup(func() { r2(); r1() })
}

func asPhoneWithNoWrapper(t *testing.T) {
	t.Helper()
	r1 := UseCapabilityDetector(func() Capability { return Capability{Status: Usable, Kind: KindAndroidTEE} })
	r2 := UseSeedWrapper(nil)
	t.Cleanup(func() { r2(); r1() })
}

// The black box holds the seed on its sealed volume and the envelope says so.
func TestASealedHostStoresTheIdentityRootSeedAndSaysItIsTheVolume(t *testing.T) {
	asSealedHost(t)
	dir := t.TempDir()
	if err := CheckRootSeedMayLiveHere(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := StoreIdentityRootSeed(dir, theSeed()); err != nil {
		t.Fatalf("a sealed host refused a root identity: %v", err)
	}
	p, scheme, _, err := RootSeedProtection(dir)
	if err != nil || p != ProtectionSealedVolume || scheme != SealedVolumeScheme {
		t.Fatalf("envelope says %q/%q (%v)", p, scheme, err)
	}
	if got, err := LoadRootSeed(dir); err != nil || !bytes.Equal(got, theSeed()) {
		t.Fatalf("round trip: %v", err)
	}
}

// The sealed-volume scheme is only available inside a sealed machine: a desktop
// with a TPM (or anything else) cannot use it to pass the gate.
func TestTheSealedVolumeSchemeIsNotAvailableOutsideASealedMachine(t *testing.T) {
	for name, c := range map[string]Capability{
		"desktop with a TPM": {Status: Usable, Kind: KindTPM2},
		"sealed but denied":  {Status: Present, Kind: KindSEVSNP},
		"unknown":            {Status: Unknown},
		"absent":             {Status: Absent},
	} {
		t.Run(name, func(t *testing.T) {
			r1 := UseCapabilityDetector(func() Capability { return c })
			r2 := UseSeedWrapper(SealedVolumeSeedWrapper())
			defer func() { r2(); r1() }()
			dir := t.TempDir()
			if err := StoreIdentityRootSeed(dir, theSeed()); !IsRootSeedRefusal(err) {
				t.Fatalf("want refusal, got %v", err)
			}
			if _, serr := os.Stat(rootSeedPath(dir)); !errors.Is(serr, os.ErrNotExist) {
				t.Fatalf("a seed file exists after a refusal: %v", serr)
			}
		})
	}
}

// A phone whose Keystore was never reported is still Unknown, and is refused.
func TestAPhoneThatNeverReportedItsKeystoreIsRefused(t *testing.T) {
	asPhoneWithNoWrapper(t)
	r := UseCapabilityDetector(func() Capability { return Unproven("app_did_not_report_key_protection", "") })
	defer r()
	if err := CheckRootSeedMayLiveHere(t.TempDir()); !IsRootSeedRefusal(err) {
		t.Fatalf("want refusal, got %v", err)
	}
}

// A production Windows or Linux desktop: usable TPM, no wrapper, not a phone.
func TestAProductionDesktopStillRefusesToHoldARootIdentity(t *testing.T) {
	r1 := UseCapabilityDetector(func() Capability { return Capability{Status: Usable, Kind: KindTPM2} })
	r2 := UseSeedWrapper(nil)
	defer func() { r2(); r1() }()
	dir := t.TempDir()
	if err := CheckRootSeedMayLiveHere(t.TempDir()); !IsRootSeedRefusal(err) {
		t.Fatalf("check: want refusal, got %v", err)
	}
	if err := StoreIdentityRootSeed(dir, theSeed()); !IsRootSeedRefusal(err) {
		t.Fatalf("store: want refusal, got %v", err)
	}
	if _, serr := os.Stat(rootSeedPath(dir)); !errors.Is(serr, os.ErrNotExist) {
		t.Fatal("a seed file exists after a refusal")
	}
}

func TestAWrappedSeedRecordsItIsHardwareWrapped(t *testing.T) {
	machine(t, Capability{Status: Usable, Kind: KindTPM2}, true)
	dir := t.TempDir()
	if err := StoreIdentityRootSeed(dir, theSeed()); err != nil {
		t.Fatal(err)
	}
	if p, _, _, _ := RootSeedProtection(dir); p != ProtectionHardwareWrapped {
		t.Fatalf("got %q", p)
	}
}
