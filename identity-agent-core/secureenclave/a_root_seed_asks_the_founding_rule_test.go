package secureenclave

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"identity-agent-core/buildmode"
)

// Every test in this package that is about something other than the founding
// rule runs on a platform that may found, the way a phone or a sealed machine
// does. The tests below replace it with the verdicts that matter.
func init() {
	foundingVerdictHere = func(string) FoundingVerdict { return FoundingVerdict{Permitted: true, Platform: "test"} }
}

func productionMac(t *testing.T) {
	t.Helper()
	r1 := UseCapabilityDetector(func() Capability { return Capability{Status: Usable, Kind: KindAppleEnclave} })
	r2 := UseSeedWrapper(fakeWorkingWrapper{})
	r3 := UseFoundingVerdict(func() FoundingVerdict {
		return FoundingVerdict{Platform: "macos", Why: CannotProveItsSoftware, Instead: ActForOneInstead}
	})
	t.Cleanup(func() { r3(); r2(); r1() })
}

type fakeWorkingWrapper struct{}

func (fakeWorkingWrapper) Available() bool                 { return true }
func (fakeWorkingWrapper) Scheme() string                  { return "fake-se" }
func (fakeWorkingWrapper) Wrap(p []byte) ([]byte, error)   { return xorFake(p), nil }
func (fakeWorkingWrapper) Unwrap(b []byte) ([]byte, error) { return xorFake(b), nil }

// A production Mac has a usable enclave and a working wrapper, and still may not
// hold a person's root seed: it is refused by the rule founding uses.
func TestAProductionMacIsRefusedARootSeedAndAnIPhoneIsNot(t *testing.T) {
	productionMac(t)
	dir := t.TempDir()
	if err := CheckRootSeedMayLiveHere(t.TempDir()); !IsRootSeedRefusal(err) {
		t.Fatalf("check: a production Mac must be refused, got %v", err)
	} else if !strings.Contains(err.Error(), "cannot prove") {
		t.Fatalf("the refusal should give the founding reason: %v", err)
	}
	if err := StoreIdentityRootSeed(dir, theSeed()); !IsRootSeedRefusal(err) {
		t.Fatalf("store: a production Mac must be refused, got %v", err)
	}
	if _, serr := os.Stat(rootSeedPath(dir)); !errors.Is(serr, os.ErrNotExist) {
		t.Fatal("a seed file exists after the refusal")
	}

	// An iPhone: same enclave, same wrapper, and a platform that attests.
	r := UseFoundingVerdict(func() FoundingVerdict { return FoundingVerdict{Permitted: true, Platform: "ios"} })
	defer r()
	if err := StoreIdentityRootSeed(dir, theSeed()); err != nil {
		t.Fatalf("an iPhone was refused: %v", err)
	}
}

// A development build is exempt, as the founding gate is.
func TestADevelopmentMacMayHoldARootSeed(t *testing.T) {
	productionMac(t)
	if !buildmode.IsDev() {
		t.Skip("production build")
	}
	if err := CheckRootSeedMayLiveHere(t.TempDir()); err != nil {
		t.Fatalf("dev build refused: %v", err)
	}
}

// ---- the sealed volume must be the storage, not just the device ----

func fakeMachine(t *testing.T, mountinfo string, uuids map[string]string) {
	t.Helper()
	root := t.TempDir()
	mi := filepath.Join(root, "mountinfo")
	if err := os.WriteFile(mi, []byte(mountinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	sys := filepath.Join(root, "sys")
	for mm, u := range uuids {
		d := filepath.Join(sys, "dev", "block", mm, "dm")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "uuid"), []byte(u+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pm, ps := mountInfoPath, sysfsRoot
	mountInfoPath, sysfsRoot = mi, sys
	t.Cleanup(func() { mountInfoPath, sysfsRoot = pm, ps })
}

const rootOnly = "20 1 254:0 / / rw,relatime shared:1 - ext4 /dev/vda1 rw\n"
const withVolume = rootOnly +
	"41 20 253:0 / /var/lib/identity-agent rw,noatime shared:2 - ext4 /dev/mapper/tenant-data rw\n"

func TestTheDataDirectoryMustBeOnAnEncryptedVolume(t *testing.T) {
	const dir = "/var/lib/identity-agent/secureenclave"
	cases := map[string]struct {
		mountinfo string
		uuids     map[string]string
		wantErr   string
	}{
		"mounted on a dm-crypt volume":   {withVolume, map[string]string{"253:0": "CRYPT-LUKS2-abc-tenant-data"}, ""},
		"plain dm-crypt":                 {withVolume, map[string]string{"253:0": "CRYPT-PLAIN-tenant-data"}, ""},
		"volume missing: root fs":        {rootOnly, nil, "not a device-mapper volume"},
		"on device-mapper but not crypt": {withVolume, map[string]string{"253:0": "LVM-xyz"}, "not an encrypted volume"},
		"no mount table":                 {"", nil, "not on any mount"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fakeMachine(t, c.mountinfo, c.uuids)
			err := dataDirIsOnADmCryptVolume(dir)
			if c.wantErr == "" && err != nil {
				t.Fatalf("want ok, got %v", err)
			}
			if c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
				t.Fatalf("want %q, got %v", c.wantErr, err)
			}
		})
	}
}

func TestAMountPointWithASpaceAndAMoreSpecificMountAreRead(t *testing.T) {
	fakeMachine(t, rootOnly+
		"41 20 253:0 / /var/lib/identity-agent rw - ext4 /dev/mapper/a rw\n"+
		"42 41 254:0 / /var/lib/identity-agent/plain rw - ext4 /dev/vda2 rw\n",
		map[string]string{"253:0": "CRYPT-LUKS2-x"})
	if err := dataDirIsOnADmCryptVolume("/var/lib/identity-agent/data"); err != nil {
		t.Fatal(err)
	}
	if err := dataDirIsOnADmCryptVolume("/var/lib/identity-agent/plain/x"); err == nil {
		t.Fatal("a plain mount inside the volume is not encrypted")
	}
	if got := unescapeMountField(`/mnt/my\040disk`); got != "/mnt/my disk" {
		t.Fatalf("got %q", got)
	}
}

// A confidential guest whose volume did not come up must not hold the seed and
// must say the volume is not mounted. The seed is not written.
func TestASealedGuestWithoutItsVolumeMountedRefusesTheRootSeed(t *testing.T) {
	fakeMachine(t, rootOnly, map[string]string{"254:0": ""})
	t.Setenv("AGENT_DATA_DIR", "/var/lib/identity-agent")
	r1 := UseCapabilityDetector(func() Capability { return Capability{Status: Usable, Kind: KindSEVSNP} })
	r2 := UseSeedWrapper(SealedVolumeSeedWrapper())
	defer func() { r2(); r1() }()

	err := CheckRootSeedMayLiveHere("/var/lib/identity-agent")
	if !IsRootSeedRefusal(err) || !strings.Contains(err.Error(), "sealed volume is not mounted") {
		t.Fatalf("want a refusal saying the sealed volume is not mounted, got %v", err)
	}
	dir := t.TempDir()
	if err := StoreIdentityRootSeed(dir, theSeed()); !IsRootSeedRefusal(err) {
		t.Fatalf("store: %v", err)
	}
	if _, serr := os.Stat(rootSeedPath(dir)); !errors.Is(serr, os.ErrNotExist) {
		t.Fatal("a seed file exists after the refusal")
	}

	// And with the volume mounted the same machine is allowed.
	fakeMachine(t, withVolume, map[string]string{"253:0": "CRYPT-LUKS2-x"})
	if err := CheckRootSeedMayLiveHere("/var/lib/identity-agent"); err != nil {
		t.Fatalf("mounted sealed guest refused: %v", err)
	}
}

// ---- an existing root seed in the clear ----

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var out bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(prev) })
	rootIdentityMisplacedWarning = sync.Once{}
	t.Cleanup(func() { rootIdentityMisplacedWarning = sync.Once{} })
	return &out
}

func plainEnvelopeFor(t *testing.T, dir, holder string) {
	t.Helper()
	if err := storeSeedAs(dir, theSeed(), nil, false, holder); err != nil {
		t.Fatal(err)
	}
}

func inProduction(t *testing.T) {
	t.Helper()
	if buildmode.IsDev() {
		t.Skip("development build")
	}
}

// A person's root seed on a production Mac, where the wrapper WORKS, is reported
// loudly and once whether it is plaintext or already wrapped, and is kept. A
// plaintext one is never re-wrapped into looking legitimate and is never served
// (owner's rule, 2026-11-05: no production running without hardware key
// protection): every use of it gets the root-seed refusal. A wrapped one is
// under the hardware key and is served.
func TestAPersonsRootSeedOnAProductionMacIsSaidLoudlyOnceWhateverItsWrapping(t *testing.T) {
	inProduction(t)
	for _, wrapped := range []bool{false, true} {
		name := "plaintext"
		if wrapped {
			name = "wrapped"
		}
		t.Run(name, func(t *testing.T) {
			productionMac(t) // a usable enclave AND a working wrapper
			out := captureLog(t)
			dir := t.TempDir()
			var w SeedWrapper
			if wrapped {
				w = fakeWorkingWrapper{}
			}
			if err := storeSeedAs(dir, theSeed(), w, false, holderIdentity); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(rootSeedPath(dir))
			for i := 0; i < 3; i++ {
				seed, err := LoadRootSeed(dir)
				if wrapped {
					if err != nil {
						t.Fatal(err)
					}
					continue
				}
				if !IsRootSeedRefusal(err) || seed != nil {
					t.Fatalf("production served a misplaced unwrapped root seed (%d bytes): %v", len(seed), err)
				}
				if !strings.Contains(err.Error(), "may not hold one") {
					t.Fatalf("the refusal should say the machine may not hold it: %v", err)
				}
			}
			if n := strings.Count(out.String(), "A PERSON'S ROOT SEED IS STORED HERE"); n != 1 {
				t.Fatalf("want exactly one loud line, got %d:\n%s", n, out.String())
			}
			after, err := os.ReadFile(rootSeedPath(dir))
			if err != nil {
				t.Fatalf("the seed must be kept: %v", err)
			}
			if string(before) != string(after) {
				t.Fatalf("the seed file was rewritten:\n%s\n->\n%s", before, after)
			}
		})
	}
}

// The pre-envelope file (the raw seed bytes) is the same case: a person's root
// seed on a production Mac is refused, left byte-for-byte as it is, and a
// development build keeps serving it (flagged in ReportSeedProtection).
func TestALegacyRootSeedOnAProductionMacIsRefusedAndADevelopmentBuildServesIt(t *testing.T) {
	productionMac(t)
	pd := isDevBuild
	t.Cleanup(func() { isDevBuild = pd })
	captureLog(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(rootSeedPath(dir)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootSeedPath(dir), theSeed(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RecordSeedOrigin(dir, SeedFromPhrase); err != nil {
		t.Fatal(err)
	}

	isDevBuild = func() bool { return false }
	if seed, err := LoadRootSeed(dir); !IsRootSeedRefusal(err) || seed != nil {
		t.Fatalf("production served a legacy root seed on a Mac (%d bytes): %v", len(seed), err)
	}
	if raw, _ := os.ReadFile(rootSeedPath(dir)); !bytes.Equal(raw, theSeed()) {
		t.Fatalf("the refused legacy file was changed: %q", raw)
	}

	// The same file through an unwrapped envelope, in development: served.
	plain := t.TempDir()
	plainEnvelopeFor(t, plain, holderIdentity)
	isDevBuild = func() bool { return true }
	if seed, err := LoadRootSeed(plain); err != nil || !bytes.Equal(seed, theSeed()) {
		t.Fatalf("a development build must keep serving it: %v", err)
	}
}

// An envelope written before `holder` existed is recognised as a person's root by
// the origin the machine recorded.
func TestAnOlderEnvelopeIsRecognisedAsARootSeedByItsRecordedOrigin(t *testing.T) {
	inProduction(t)
	productionMac(t)
	out := captureLog(t)
	dir := t.TempDir()
	if err := storeSeedAs(dir, theSeed(), nil, false, ""); err != nil {
		t.Fatal(err)
	}
	if err := RecordSeedOrigin(dir, SeedFromPhrase); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRootSeed(dir); !IsRootSeedRefusal(err) {
		t.Fatalf("production served an older, unwrapped root seed on a Mac: %v", err)
	}
	if !strings.Contains(out.String(), "A PERSON'S ROOT SEED IS STORED HERE") {
		t.Fatalf("an older root seed was not reported:\n%s", out.String())
	}
}

// The legacy raw-bytes file keeps whose seed it is through migration.
func TestTheLegacyMigrationKeepsTheHolder(t *testing.T) {
	inProduction(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(rootSeedPath(dir)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootSeedPath(dir), theSeed(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RecordSeedOrigin(dir, SeedFromPhrase); err != nil {
		t.Fatal(err)
	}
	// A phone: allowed to hold it, so migration runs.
	r1 := UseCapabilityDetector(func() Capability { return Capability{Status: Usable, Kind: KindAppleEnclave} })
	r2 := UseSeedWrapper(fakeWorkingWrapper{})
	r3 := UseFoundingVerdict(func() FoundingVerdict { return FoundingVerdict{Permitted: true, Platform: "ios"} })
	defer func() { r3(); r2(); r1() }()
	if _, err := LoadRootSeed(dir); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(rootSeedPath(dir))
	if !strings.Contains(string(raw), fmt.Sprintf(`"holder":%q`, holderIdentity)) {
		t.Fatalf("holder lost in migration: %s", raw)
	}
}

// The mount check looks at the directory actually written, not a default.
func TestTheDirectoryBeingWrittenIsTheOneChecked(t *testing.T) {
	fakeMachine(t, withVolume, map[string]string{"253:0": "CRYPT-LUKS2-x"})
	t.Setenv("AGENT_DATA_DIR", "/var/lib/identity-agent") // the default is fine...
	r1 := UseCapabilityDetector(func() Capability { return Capability{Status: Usable, Kind: KindSEVSNP} })
	r2 := UseSeedWrapper(SealedVolumeSeedWrapper())
	defer func() { r2(); r1() }()
	if err := CheckRootSeedMayLiveHere("/var/lib/identity-agent"); err != nil {
		t.Fatal(err)
	}
	// ...and a directory elsewhere, on the plain root, is not.
	if err := CheckRootSeedMayLiveHere("/srv/data"); !IsRootSeedRefusal(err) {
		t.Fatalf("a data directory off the volume was allowed: %v", err)
	}
	if err := StoreIdentityRootSeed("/srv/data", theSeed()); !IsRootSeedRefusal(err) {
		t.Fatalf("store off the volume: %v", err)
	}
}

// A machine's own seed, held unwrapped on a desktop, is not a root identity and
// is not reported as a misplaced one. In production it is still refused, as every
// unwrapped seed is.
func TestAMachinesOwnPlaintextSeedIsNotReported(t *testing.T) {
	inProduction(t)
	productionMac(t)
	UseSeedWrapper(nil)
	out := captureLog(t)
	dir := t.TempDir()
	plainEnvelopeFor(t, dir, holderDevice)
	if _, err := LoadRootSeed(dir); !IsRootSeedRefusal(err) {
		t.Fatalf("a production build served an unwrapped seed: %v", err)
	}
	if strings.Contains(out.String(), "ROOT SEED IS STORED HERE") {
		t.Fatalf("reported a machine's own seed:\n%s", out.String())
	}
}

// Where the platform now has a protection, the plaintext root seed is re-wrapped
// and keeps its holder.
func TestAPlaintextRootSeedIsRewrappedWhereAProtectionNowExists(t *testing.T) {
	inProduction(t)
	dir := t.TempDir()
	plainEnvelopeFor(t, dir, holderIdentity)
	r1 := UseCapabilityDetector(func() Capability { return Capability{Status: Usable, Kind: KindAppleEnclave} })
	r2 := UseSeedWrapper(fakeWorkingWrapper{})
	defer func() { r2(); r1() }()
	if _, err := LoadRootSeed(dir); err != nil {
		t.Fatal(err)
	}
	p, scheme, _, _ := RootSeedProtection(dir)
	if p != ProtectionHardwareWrapped || scheme != "fake-se" {
		t.Fatalf("not re-wrapped: %q/%q", p, scheme)
	}
	raw, _ := os.ReadFile(rootSeedPath(dir))
	if !strings.Contains(string(raw), fmt.Sprintf(`"holder":%q`, holderIdentity)) {
		t.Fatalf("holder lost on re-wrap: %s", raw)
	}
}
