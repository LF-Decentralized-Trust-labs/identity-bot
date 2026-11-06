package secureenclave

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

const aPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func asBuild(t *testing.T, dev bool) {
	t.Helper()
	prev := isDevBuild
	isDevBuild = func() bool { return dev }
	t.Cleanup(func() { isDevBuild = prev })
}

// The phrase recreates the root seed, so on a machine that can wrap the seed it
// is held wrapped, and the words are nowhere in the file.
func TestAHeldPhraseIsWrappedAndNotInTheFile(t *testing.T) {
	asBuild(t, false)
	machine(t, Capability{Status: Usable, Kind: KindTPM2}, true)
	dir := t.TempDir()
	if err := StoreRecoveryPhrase(dir, []byte(aPhrase)); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(recoveryPhrasePath(dir))
	if bytes.Contains(raw, []byte("abandon")) {
		t.Fatalf("the words are in the file: %s", raw)
	}
	if p, scheme, ok := RecoveryPhraseProtection(dir); !ok || p != ProtectionHardwareWrapped || scheme != "fake" {
		t.Fatalf("got %q %q %v", p, scheme, ok)
	}
	got, err := LoadRecoveryPhrase(dir)
	if err != nil || string(got) != aPhrase {
		t.Fatalf("got %q, %v", got, err)
	}
}

// A production build holds the phrase only where it can wrap it: no wrapper, or
// key hardware that is not proven usable, is the root-seed refusal and nothing
// is written. This is the case the app's own secure storage used to cover in
// software.
func TestAProductionBuildRefusesToHoldAPhraseItCannotWrap(t *testing.T) {
	for name, c := range map[string]struct {
		cap     Capability
		wrapper bool
	}{
		"hardware but no working wrapper":  {Capability{Status: Usable, Kind: KindTPM2}, false},
		"a wrapper but no proven hardware": {Capability{Status: Unknown}, true},
	} {
		t.Run(name, func(t *testing.T) {
			asBuild(t, false)
			machine(t, c.cap, c.wrapper)
			dir := t.TempDir()
			err := StoreRecoveryPhrase(dir, []byte(aPhrase))
			if !IsRootSeedRefusal(err) {
				t.Fatalf("got %v", err)
			}
			if _, statErr := os.Stat(recoveryPhrasePath(dir)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("something was written: %v", statErr)
			}
		})
	}
}

// A phrase that is not on a founding-capable machine is still wrapped: the
// founding rule is about the identity, the wrapping rule about the phrase.
func TestAPhraseIsWrappedWhereAnIdentityMayNotBeFounded(t *testing.T) {
	asBuild(t, false)
	machine(t, Capability{Status: Usable, Kind: KindAppleEnclave}, true)
	t.Cleanup(UseFoundingVerdict(func() FoundingVerdict { return FoundingVerdict{Permitted: false, Platform: "macos"} }))
	if err := StoreRecoveryPhrase(t.TempDir(), []byte(aPhrase)); err != nil {
		t.Fatal(err)
	}
}

// Development keeps working, flagged: held unwrapped, said to be unwrapped, and
// refused the moment the same files are met by a production build.
func TestADevelopmentBuildHoldsItUnwrappedAndAProductionBuildWillNotServeIt(t *testing.T) {
	machine(t, Capability{Status: Unknown}, false)
	dir := t.TempDir()
	asBuild(t, true)
	if err := StoreRecoveryPhrase(dir, []byte(aPhrase)); err != nil {
		t.Fatal(err)
	}
	if p, _, _ := RecoveryPhraseProtection(dir); p != ProtectionUnwrapped {
		t.Fatalf("got %q", p)
	}
	if got, err := LoadRecoveryPhrase(dir); err != nil || string(got) != aPhrase {
		t.Fatalf("development should still read it: %q %v", got, err)
	}
	asBuild(t, false)
	if _, err := LoadRecoveryPhrase(dir); !IsRootSeedRefusal(err) {
		t.Fatalf("production served an unwrapped phrase: %v", err)
	}
}

// A wrapper that hands the key back in the clear protects nothing.
type leakyWrap struct{ fakeWrap }

func (leakyWrap) Wrap(p []byte) ([]byte, error) { return append([]byte("k:"), p...), nil }

func TestAWrapperThatLeaksTheKeyIsRefused(t *testing.T) {
	asBuild(t, false)
	machine(t, Capability{Status: Usable, Kind: KindTPM2}, true)
	r := UseSeedWrapper(leakyWrap{fakeWrap{true}})
	defer r()
	dir := t.TempDir()
	if err := StoreRecoveryPhrase(dir, []byte(aPhrase)); err == nil {
		t.Fatal("recorded as wrapped")
	}
	if _, err := os.Stat(recoveryPhrasePath(dir)); err == nil {
		t.Fatal("written")
	}
}

// A phrase longer than an RSA-OAEP block (the TPM wrapper) is held: the wrapper
// only ever sees a 32-byte key.
func TestAPhraseLongerThanTheWrapperCanCarryIsHeld(t *testing.T) {
	asBuild(t, false)
	machine(t, Capability{Status: Usable, Kind: KindTPM2}, true)
	long := bytes.TrimSpace(bytes.Repeat([]byte("abandonxx "), 24))
	dir := t.TempDir()
	if err := StoreRecoveryPhrase(dir, long); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadRecoveryPhrase(dir); err != nil || !bytes.Equal(got, long) {
		t.Fatalf("%q %v", got, err)
	}
}

func TestForgettingIsConfirmedAndNothingHeldIsNotAnError(t *testing.T) {
	asBuild(t, false)
	machine(t, Capability{Status: Usable, Kind: KindTPM2}, true)
	dir := t.TempDir()
	if err := ForgetRecoveryPhrase(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecoveryPhrase(dir); !errors.Is(err, ErrNoRecoveryPhrase) {
		t.Fatalf("got %v", err)
	}
	if err := StoreRecoveryPhrase(dir, []byte(aPhrase)); err != nil {
		t.Fatal(err)
	}
	if err := ForgetRecoveryPhrase(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecoveryPhrase(dir); !errors.Is(err, ErrNoRecoveryPhrase) {
		t.Fatalf("still held: %v", err)
	}
}

// A damaged envelope is an error, never "no phrase": the caller must not treat
// it as nothing to migrate and overwrite it.
func TestADamagedPhraseIsNotNoPhrase(t *testing.T) {
	asBuild(t, false)
	machine(t, Capability{Status: Usable, Kind: KindTPM2}, true)
	dir := t.TempDir()
	if err := StoreRecoveryPhrase(dir, []byte(aPhrase)); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(recoveryPhrasePath(dir))
	raw = bytes.Replace(raw, []byte(`"sealed":"`), []byte(`"sealed":"AAAA`), 1)
	_ = os.WriteFile(recoveryPhrasePath(dir), raw, 0600)
	_, err := LoadRecoveryPhrase(dir)
	if err == nil || errors.Is(err, ErrNoRecoveryPhrase) {
		t.Fatalf("got %v", err)
	}
}
