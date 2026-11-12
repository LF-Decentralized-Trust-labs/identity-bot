package secureenclave

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
)

// perProfileFake is a hardware element that holds a key per name, the way each
// platform now does: a wrapper made by ForKey(name) opens only what it wrote.
type perProfileFake struct {
	base  *fakeWrapper
	names []string // every name a wrapper was asked for, to prove which key was used
}

func newPerProfileFake() *perProfileFake {
	return &perProfileFake{base: &fakeWrapper{key: bytes.Repeat([]byte{9}, 32), available: true}}
}

func (p *perProfileFake) Available() bool                 { return true }
func (p *perProfileFake) Scheme() string                  { return "fake-hw" }
func (p *perProfileFake) Wrap(b []byte) ([]byte, error)   { return p.base.Wrap(b) }
func (p *perProfileFake) Unwrap(b []byte) ([]byte, error) { return p.base.Unwrap(b) }
func (p *perProfileFake) KeyNameFor(profile string) string {
	return ProfileKeyName("fake-seed-key", profile)
}
func (p *perProfileFake) ForKey(name string) SeedWrapper {
	p.names = append(p.names, name)
	k := sha256.Sum256([]byte(name))
	return &fakeWrapper{key: k[:], available: true}
}

// aGateOf stands a gate for the data directories it is given, each with a
// profile id. open says whether the identity is logged in.
type aTestGate struct {
	profile string
	open    bool
}

func (g aTestGate) Seal(p []byte) ([]byte, error) {
	out := make([]byte, len(p))
	for i, b := range p {
		out[i] = b ^ 0x5c
	}
	return append([]byte("gk1:"), out...), nil
}
func (g aTestGate) Open(s []byte) ([]byte, error) {
	if !bytes.HasPrefix(s, []byte("gk1:")) {
		return nil, errors.New("not sealed under this key")
	}
	out := make([]byte, len(s)-4)
	for i, b := range s[4:] {
		out[i] = b ^ 0x5c
	}
	return out, nil
}
func (g aTestGate) DeriveKey(info string, n int) ([]byte, error) {
	sum := sha256.Sum256([]byte(g.profile + "|" + info))
	return sum[:n], nil
}

func theGateIs(t *testing.T, dir string, g aTestGate) {
	t.Helper()
	r1 := UseGate(func(d string) (GateSealer, bool) {
		if d != dir {
			return nil, false
		}
		if !g.open {
			return nil, true
		}
		return g, true
	})
	r2 := UseProfileLookup(func(d string) string {
		if d == dir {
			return g.profile
		}
		return ""
	})
	t.Cleanup(func() { r2(); r1() })
}

func envOf(t *testing.T, dir string) seedEnvelope {
	t.Helper()
	env, err := readEnvelope(dir)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// One spelling, and one that every platform's naming accepts.
func TestAProfileKeyNameHasOneSpellingAndNoOddCharacters(t *testing.T) {
	a, b := ProfileKeyName("base.v1", "profile-a"), ProfileKeyName("base.v1", "profile-b")
	if a == b {
		t.Fatal("two profiles share a key name")
	}
	if a != ProfileKeyName("base.v1", "profile-a") {
		t.Fatal("a key name is not stable")
	}
	if !regexp.MustCompile(`^base\.v1\.p-[0-9a-f]{16}$`).MatchString(a) {
		t.Fatalf("unexpected spelling %q", a)
	}
	if strings.Contains(ProfileKeyName("x", "a/b cé"), "/") {
		t.Fatal("the profile id reached the name")
	}
}

// The case that fails if the seed is still wrapped under the device-wide key:
// the envelope names the profile's key, the two profiles' keys differ, and one
// profile's envelope does not open under the other's key.
func TestAGatedProfilesSeedIsWrappedUnderItsOwnKey(t *testing.T) {
	aDevelopmentBuild(t)
	hw := newPerProfileFake()
	withWrapper(t, hw)
	dirA, dirB := t.TempDir(), t.TempDir()
	gA, gB := aTestGate{"profile-a", true}, aTestGate{"profile-b", true}
	seed := testSeed()

	theGateIs(t, dirA, gA)
	if err := StoreDeviceLocalSeed(dirA, seed); err != nil {
		t.Fatal(err)
	}
	r := UseGate(func(d string) (GateSealer, bool) { return gB, d == dirB })
	defer r()
	r2 := UseProfileLookup(func(d string) string {
		switch d {
		case dirA:
			return "profile-a"
		case dirB:
			return "profile-b"
		}
		return ""
	})
	defer r2()
	if err := StoreDeviceLocalSeed(dirB, seed); err != nil {
		t.Fatal(err)
	}

	ea, eb := envOf(t, dirA), envOf(t, dirB)
	if ea.Key != ProfileKeyName("fake-seed-key", "profile-a") || eb.Key != ProfileKeyName("fake-seed-key", "profile-b") {
		t.Fatalf("envelopes do not name their profile's key: %q %q", ea.Key, eb.Key)
	}
	if ea.Key == eb.Key {
		t.Fatal("two profiles were wrapped under one key")
	}

	// B's envelope, put in A's place, does not open: its blob is under B's key.
	raw, _ := os.ReadFile(rootSeedPath(dirB))
	var forged seedEnvelope
	_ = json.Unmarshal(raw, &forged)
	forged.Key = ea.Key
	b, _ := json.Marshal(forged)
	if err := os.WriteFile(rootSeedPath(dirB), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRootSeed(dirB); err == nil {
		t.Fatal("a seed opened under another profile's hardware key")
	}
}

func TestAGatedProfilesSeedReadsBackUnderTheKeyItNames(t *testing.T) {
	aDevelopmentBuild(t)
	hw := newPerProfileFake()
	withWrapper(t, hw)
	dir := t.TempDir()
	theGateIs(t, dir, aTestGate{"profile-a", true})
	seed := testSeed()
	if err := StoreDeviceLocalSeed(dir, seed); err != nil {
		t.Fatal(err)
	}
	got, err := LoadRootSeed(dir)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("read back: %v", err)
	}
	want := ProfileKeyName("fake-seed-key", "profile-a")
	used := false
	for _, n := range hw.names {
		if n == want {
			used = true
		}
	}
	if !used {
		t.Fatalf("the profile's key was never asked for: %v", hw.names)
	}
}

// An envelope written before the per-profile key has no name and opens under the
// device-wide key, on a platform that now holds a key per profile. That is what
// keeps every existing identity openable, and it is why deleting the device-wide
// key is its own, last step.
func TestAnEnvelopeWithNoKeyNameStillOpensUnderTheDeviceWideKey(t *testing.T) {
	aDevelopmentBuild(t)
	hw := newPerProfileFake()
	withWrapper(t, hw)
	dir := t.TempDir()
	seed := testSeed()
	// No gate, so no profile: the device-wide key, as before.
	if err := StoreDeviceLocalSeed(dir, seed); err != nil {
		t.Fatal(err)
	}
	if k := envOf(t, dir).Key; k != "" {
		t.Fatalf("an ungated profile named a key: %q", k)
	}
	got, err := LoadRootSeed(dir)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("a device-wide envelope did not open: %v", err)
	}
}

// A platform that cannot name keys cannot open an envelope that names one, and
// says so instead of trying the wrong key.
func TestAnEnvelopeNamingAKeyIsRefusedWhereKeysCannotBeNamed(t *testing.T) {
	aDevelopmentBuild(t)
	hw := newPerProfileFake()
	withWrapper(t, hw)
	dir := t.TempDir()
	theGateIs(t, dir, aTestGate{"profile-a", true})
	if err := StoreDeviceLocalSeed(dir, testSeed()); err != nil {
		t.Fatal(err)
	}
	withWrapper(t, hw.base) // the same hardware, now without a key per name
	if _, err := LoadRootSeed(dir); err == nil || !strings.Contains(err.Error(), "cannot name") {
		t.Fatalf("expected a refusal that says keys cannot be named, got %v", err)
	}
}

func TestAHeldKeyRecordsTheProfilesKeyAndOpensUnderIt(t *testing.T) {
	aDevelopmentBuild(t)
	hw := newPerProfileFake()
	withWrapper(t, hw)
	dir := t.TempDir()
	key := bytes.Repeat([]byte{3}, 32)
	held, err := KeyToHoldUnderTheProfilesWrapper(dir, "profile-a", "gate-copy:profile-a", key)
	if err != nil {
		t.Fatal(err)
	}
	var env heldKeyEnvelope
	_ = json.Unmarshal(held, &env)
	if env.WrapKey != ProfileKeyName("fake-seed-key", "profile-a") {
		t.Fatalf("the held key does not name the profile's key: %q", env.WrapKey)
	}
	got, wrapped, err := OpenKeyHeldUnderTheWrapper("gate-copy:profile-a", held)
	if err != nil || !wrapped || !bytes.Equal(got, key) {
		t.Fatalf("held key did not open: %v", err)
	}
	// Another profile's key does not open it.
	env.WrapKey = ProfileKeyName("fake-seed-key", "profile-b")
	forged, _ := json.Marshal(env)
	if _, _, err := OpenKeyHeldUnderTheWrapper("gate-copy:profile-a", forged); err == nil {
		t.Fatal("a held key opened under another profile's key")
	}
	// The device-wide spelling is unchanged: no profile, no name.
	plain, _ := KeyToHoldUnderTheWrapper(dir, "x", key)
	var penv heldKeyEnvelope
	_ = json.Unmarshal(plain, &penv)
	if penv.WrapKey != "" {
		t.Fatalf("a profile-less key named a key: %q", penv.WrapKey)
	}
}

func TestARecoveryPhraseRecordsTheProfilesKeyAndOpensUnderIt(t *testing.T) {
	aDevelopmentBuild(t)
	hw := newPerProfileFake()
	withWrapper(t, hw)
	dir := t.TempDir()
	theGateIs(t, dir, aTestGate{"profile-a", true})
	phrase := []byte("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima")
	if err := StoreRecoveryPhrase(dir, phrase); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(recoveryPhrasePath(dir))
	var env phraseEnvelope
	_ = json.Unmarshal(raw, &env)
	if env.WrapKey != ProfileKeyName("fake-seed-key", "profile-a") {
		t.Fatalf("the phrase does not name the profile's key: %q", env.WrapKey)
	}
	got, err := LoadRecoveryPhrase(dir)
	if err != nil || !bytes.Equal(got, phrase) {
		t.Fatalf("phrase did not open: %v", err)
	}
}

// ---- Android: a Keystore alias per profile ---------------------------------

// theAppsPerProfileKeystore keeps one attested key per alias, and the device-wide
// one under no alias, the way an app that registers both hosts does.
type theAppsPerProfileKeystore struct {
	keys   map[string]*rsa.PrivateKey
	chains map[string][]byte
	asked  []string
}

func (h *theAppsPerProfileKeystore) AvailableFor(a string) bool {
	h.asked = append(h.asked, a)
	return h.keys[a] != nil
}
func (h *theAppsPerProfileKeystore) AttestationChainFor(a string) []byte { return h.chains[a] }
func (h *theAppsPerProfileKeystore) UnwrapKeyFor(a string, w []byte) ([]byte, error) {
	k := h.keys[a]
	if k == nil {
		return nil, errors.New("no such key")
	}
	return oaepDecryptSHA256MGF1SHA1(k, w)
}

func anAppWithAKeystoreKeyPerProfile(t *testing.T, aliases ...string) (*theAppsKeystore, *theAppsPerProfileKeystore) {
	t.Helper()
	usablePhone(t, Capability{Status: Usable, Kind: "android_strongbox"})
	device := theApp(t, aKeyIn(attestStrongBox), true) // pins the test root and registers the device-wide host
	ph := &theAppsPerProfileKeystore{keys: map[string]*rsa.PrivateKey{}, chains: map[string][]byte{}}
	for _, a := range aliases {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		spec := aKeyIn(attestStrongBox)
		spec.leafKey = &k.PublicKey
		chain, root := builtChain(t, spec)
		// every chain here is built under its own test root; trust them all
		attestationRoots = append(attestationRoots, root)
		ph.keys[a], ph.chains[a] = k, chain
	}
	DeclareProfileSeedWrapHost(ph)
	t.Cleanup(func() { DeclareProfileSeedWrapHost(nil) })
	return device, ph
}

func TestAnAndroidProfileUsesItsOwnKeystoreAlias(t *testing.T) {
	aDevelopmentBuild(t)
	nameA := ProfileKeyName(androidSeedAliasBase, "profile-a")
	nameB := ProfileKeyName(androidSeedAliasBase, "profile-b")
	_, ph := anAppWithAKeystoreKeyPerProfile(t, nameA, nameB)
	w := declaredHostSeedWrapper()
	defer UseSeedWrapper(w)()

	dir := t.TempDir()
	theGateIs(t, dir, aTestGate{"profile-a", true})
	seed := testSeed()
	if err := StoreDeviceLocalSeed(dir, seed); err != nil {
		t.Fatal(err)
	}
	if k := envOf(t, dir).Key; k != nameA {
		t.Fatalf("the envelope names %q, not the profile's alias %q", k, nameA)
	}
	got, err := LoadRootSeed(dir)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("a profile's seed did not open through its alias: %v", err)
	}
	// Profile B's hardware key cannot open profile A's seed: the app's key for
	// that alias is a different key.
	raw, _ := os.ReadFile(rootSeedPath(dir))
	var env seedEnvelope
	_ = json.Unmarshal(raw, &env)
	env.Key = nameB
	b, _ := json.Marshal(env)
	_ = os.WriteFile(rootSeedPath(dir), b, 0o600)
	if _, err := LoadRootSeed(dir); err == nil {
		t.Fatal("a seed opened under another profile's Keystore alias")
	}
	if len(ph.asked) == 0 {
		t.Fatal("the per-profile host was never asked")
	}
}

// An app that has not registered a per-profile host keeps one key for every
// profile and the envelope names none, so nothing it already wrote stops opening.
func TestAnAndroidAppWithNoPerProfileHostKeepsTheDeviceWideKey(t *testing.T) {
	aDevelopmentBuild(t)
	usablePhone(t, Capability{Status: Usable, Kind: "android_strongbox"})
	theApp(t, aKeyIn(attestStrongBox), true)
	defer UseSeedWrapper(declaredHostSeedWrapper())()
	dir := t.TempDir()
	theGateIs(t, dir, aTestGate{"profile-a", true})
	if err := StoreDeviceLocalSeed(dir, testSeed()); err != nil {
		t.Fatal(err)
	}
	if k := envOf(t, dir).Key; k != "" {
		t.Fatalf("with no per-profile host the envelope named %q", k)
	}
	if _, err := LoadRootSeed(dir); err != nil {
		t.Fatal(err)
	}
}

// ---- the controller key of a desktop ---------------------------------------

func TestAControllerKeyIsSealedUnderTheGateAndLockedWhenItIs(t *testing.T) {
	dir := t.TempDir()
	blob := bytes.Repeat([]byte{0x42}, 40)
	theGateIs(t, dir, aTestGate{"profile-a", true})

	sealed, scheme, err := sealForTheGate(dir, blob)
	if err != nil || scheme != gateScheme {
		t.Fatalf("seal: %v %q", err, scheme)
	}
	if bytes.Contains(sealed, blob) {
		t.Fatal("the controller key blob is in the sealed bytes")
	}
	got, needs, err := openFromTheGate(dir, sealed, scheme)
	if err != nil || needs || !bytes.Equal(got, blob) {
		t.Fatalf("open: %v needs=%v", err, needs)
	}

	// Locked: whatever is on disk, there is no key and nothing is made.
	theGateIs(t, dir, aTestGate{"profile-a", false})
	if _, _, err := openFromTheGate(dir, sealed, scheme); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("a locked profile gave up its controller key: %v", err)
	}
	if _, _, err := openFromTheGate(dir, blob, ""); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("a locked profile served a plain blob: %v", err)
	}
	if _, _, err := sealForTheGate(dir, blob); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("a locked profile wrote a controller key: %v", err)
	}
}

func TestAControllerKeyMadeBeforeTheGateIsServedAndMarkedForSealing(t *testing.T) {
	dir := t.TempDir()
	blob := bytes.Repeat([]byte{0x42}, 40)
	theGateIs(t, dir, aTestGate{"profile-a", true})
	got, needs, err := openFromTheGate(dir, blob, "")
	if err != nil || !needs || !bytes.Equal(got, blob) {
		t.Fatalf("legacy blob: %v needs=%v", err, needs)
	}
	// An ungated profile writes and reads it as it always did.
	other := t.TempDir()
	s, scheme, err := sealForTheGate(other, blob)
	if err != nil || scheme != "" || !bytes.Equal(s, blob) {
		t.Fatalf("an ungated profile's blob changed: %v %q", err, scheme)
	}
	if _, _, err := openFromTheGate(dir, blob, "some-other-gate"); err == nil {
		t.Fatal("an unknown gate scheme was opened")
	}
}

func TestTheTPMAuthorizationIsDerivedFromTheGateAndRefusedWhenLocked(t *testing.T) {
	dir := t.TempDir()
	theGateIs(t, dir, aTestGate{"profile-a", true})
	a, err := tpmAuthorizationFor(dir)
	if err != nil || len(a) != tpmAuthLen {
		t.Fatalf("authorization: %v (%d bytes)", err, len(a))
	}
	want, _ := aTestGate{"profile-a", true}.DeriveKey("tpm-auth", tpmAuthLen)
	if !bytes.Equal(a, want) {
		t.Fatal("the authorization value is not derived with the purpose \"tpm-auth\"")
	}
	// Another purpose, another key; another profile, another value.
	if o, _ := (aTestGate{"profile-a", true}).DeriveKey("something-else", tpmAuthLen); bytes.Equal(a, o) {
		t.Fatal("two purposes share a key")
	}
	other := t.TempDir()
	theGateIs(t, other, aTestGate{"profile-b", true})
	if b, _ := tpmAuthorizationFor(other); bytes.Equal(a, b) {
		t.Fatal("two profiles share an authorization value")
	}

	theGateIs(t, dir, aTestGate{"profile-a", false})
	if _, err := tpmAuthorizationFor(dir); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("a locked profile produced an authorization value: %v", err)
	}
	// A profile with no gate has none: the key was made without one.
	if v, err := tpmAuthorizationFor(t.TempDir()); err != nil || v != nil {
		t.Fatalf("an ungated profile got an authorization value: %v %v", v, err)
	}
}

// A gate that cannot derive is a refusal, never a key with no authorization.
type aGateThatCannotDerive struct{ aTestGate }

func (aGateThatCannotDerive) DeriveKey(string, int) ([]byte, error) { panic("not reached") }

func TestAGateThatCannotDeriveRefusesInsteadOfLeavingTheTPMKeyOpen(t *testing.T) {
	dir := t.TempDir()
	r := UseGate(func(d string) (GateSealer, bool) { return onlySeals{aTestGate{"p", true}}, true })
	defer r()
	if v, err := tpmAuthorizationFor(dir); err == nil || v != nil {
		t.Fatalf("expected a refusal, got %v %v", v, err)
	}
}

// onlySeals hides DeriveKey.
type onlySeals struct{ g aTestGate }

func (o onlySeals) Seal(b []byte) ([]byte, error) { return o.g.Seal(b) }
func (o onlySeals) Open(b []byte) ([]byte, error) { return o.g.Open(b) }

func TestTheControllerKeyNameIsTheProfilesOwnWhenItHasAGate(t *testing.T) {
	dir := t.TempDir()
	if n := controllerKeyNameFor("IdentityAgentMachineKey.v1", dir); n != "IdentityAgentMachineKey.v1" {
		t.Fatalf("an ungated profile's key was renamed: %q", n)
	}
	theGateIs(t, dir, aTestGate{"profile-a", true})
	if n := controllerKeyNameFor("IdentityAgentMachineKey.v1", dir); n != ProfileKeyName("IdentityAgentMachineKey.v1", "profile-a") {
		t.Fatalf("a gated profile's key name: %q", n)
	}
}

// The core hands the provider the value as hex wide text with a terminator and
// computes no digest of its own.
func TestTheUsageAuthIsTheHexTextAsAWideStringWithItsTerminator(t *testing.T) {
	w := tpmUsageAuthWide([]byte{0x00, 0xff, 0x10})
	want := []uint16{'0', '0', 'f', 'f', '1', '0', 0}
	if len(w) != len(want) {
		t.Fatalf("got %v", w)
	}
	for i := range want {
		if w[i] != want[i] {
			t.Fatalf("got %v, want %v", w, want)
		}
	}
}

// A locked desktop profile is a signer that exists and signs nothing. It must not
// be the software signer: that is a different key in a plain file.
func TestALockedProfilesControllerKeyIsNotTheSoftwareSigner(t *testing.T) {
	dir := t.TempDir()
	theGateIs(t, dir, aTestGate{"profile-a", false})
	prev := controllerKeyIsHardwareHere
	controllerKeyIsHardwareHere = func() (string, string) { return "secure_enclave", "Apple Secure Enclave" }
	defer func() { controllerKeyIsHardwareHere = prev }()

	s := NewPlatformSigner(dir)
	if s.Platform() == "software" {
		t.Fatal("a locked profile fell through to the software signer")
	}
	if _, err := s.Sign([]byte("x")); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("a locked controller key signed: %v", err)
	}
	if _, err := s.PublicKey(); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("a locked controller key gave its public key: %v", err)
	}
	if _, err := os.Stat(dir + "/secureenclave/software_signer.key"); err == nil {
		t.Fatal("a software key was minted for a locked profile")
	}
}
