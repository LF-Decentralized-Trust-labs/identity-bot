package secureenclave

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

const anotherPhrase = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"

// While an identity moves to a new phrase both phrases are needed, and losing
// either loses the identity (ADR-061 section 10). The one moved to is wrapped
// as the one in force is, in a file of its own, and neither disturbs the other.
func TestThePhraseMovedToIsWrappedBesideThePhraseInForce(t *testing.T) {
	asBuild(t, false)
	machine(t, Capability{Status: Usable, Kind: KindTPM2}, true)
	dir := t.TempDir()
	if err := StoreRecoveryPhrase(dir, []byte(aPhrase)); err != nil {
		t.Fatal(err)
	}
	if err := StorePhraseMovingTo(dir, []byte(anotherPhrase)); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(phraseMovingToPath(dir))
	if bytes.Contains(raw, []byte("zoo")) {
		t.Fatalf("the words are in the file: %s", raw)
	}
	if p, _, ok := PhraseMovingToProtection(dir); !ok || p != ProtectionHardwareWrapped {
		t.Fatalf("got %q %v", p, ok)
	}
	if got, err := LoadPhraseMovingTo(dir); err != nil || string(got) != anotherPhrase {
		t.Fatalf("got %q, %v", got, err)
	}
	if got, err := LoadRecoveryPhrase(dir); err != nil || string(got) != aPhrase {
		t.Fatalf("the phrase in force was disturbed: %q, %v", got, err)
	}

	// Forgetting one leaves the other.
	if err := ForgetPhraseMovingTo(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPhraseMovingTo(dir); !errors.Is(err, ErrNoRecoveryPhrase) {
		t.Fatalf("got %v", err)
	}
	if got, err := LoadRecoveryPhrase(dir); err != nil || string(got) != aPhrase {
		t.Fatalf("forgetting the move forgot the phrase in force: %q, %v", got, err)
	}
}

// The second phrase meets the same refusal as the first: a production build
// that cannot wrap it holds nothing.
func TestAProductionBuildRefusesToHoldAMovedToPhraseItCannotWrap(t *testing.T) {
	asBuild(t, false)
	machine(t, Capability{Status: Usable, Kind: KindTPM2}, false)
	dir := t.TempDir()
	err := StorePhraseMovingTo(dir, []byte(anotherPhrase))
	if err == nil || !IsRootSeedRefusal(err) {
		t.Fatalf("got %v", err)
	}
	if _, serr := os.Stat(phraseMovingToPath(dir)); serr == nil {
		t.Fatal("written")
	}
}

// Neither file opens as the other: the holder is bound into the encryption.
func TestOneHeldPhraseCannotBeCopiedOverTheOther(t *testing.T) {
	asBuild(t, false)
	machine(t, Capability{Status: Usable, Kind: KindTPM2}, true)
	dir := t.TempDir()
	if err := StorePhraseMovingTo(dir, []byte(anotherPhrase)); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(phraseMovingToPath(dir))
	if err := os.WriteFile(recoveryPhrasePath(dir), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadRecoveryPhrase(dir); err == nil {
		t.Fatalf("the phrase moved to opened as the phrase in force: %q", got)
	}
}

// A different phrase is never written over the one held unless the caller says
// it is replacing it: the one held may be the only copy of an identity. The
// same phrase again is not a change. Both places a phrase is held behave alike.
func TestADifferentPhraseIsNotWrittenOverTheOneHeld(t *testing.T) {
	for name, slot := range map[string]struct {
		store, replace func(string, []byte) error
		load           func(string) ([]byte, error)
	}{
		"in force":  {StoreRecoveryPhrase, ReplaceRecoveryPhrase, LoadRecoveryPhrase},
		"moving to": {StorePhraseMovingTo, ReplacePhraseMovingTo, LoadPhraseMovingTo},
	} {
		t.Run(name, func(t *testing.T) {
			asBuild(t, false)
			machine(t, Capability{Status: Usable, Kind: KindTPM2}, true)
			dir := t.TempDir()
			if err := slot.store(dir, []byte(aPhrase)); err != nil {
				t.Fatal(err)
			}
			if err := slot.store(dir, []byte(aPhrase)); err != nil {
				t.Fatalf("the same phrase again: %v", err)
			}
			if err := slot.store(dir, []byte(anotherPhrase)); !errors.Is(err, ErrADifferentPhraseIsHeld) {
				t.Fatalf("a different phrase: got %v", err)
			}
			if got, err := slot.load(dir); err != nil || string(got) != aPhrase {
				t.Fatalf("the phrase held changed: %q, %v", got, err)
			}
			if err := slot.replace(dir, []byte(anotherPhrase)); err != nil {
				t.Fatalf("replacing: %v", err)
			}
			if got, err := slot.load(dir); err != nil || string(got) != anotherPhrase {
				t.Fatalf("not replaced: %q, %v", got, err)
			}
		})
	}
}

// A phrase held that cannot be opened to compare is not overwritten either: a
// damaged or briefly unopenable file is not "none held".
func TestAHeldPhraseThatCannotBeOpenedIsNotOverwritten(t *testing.T) {
	asBuild(t, false)
	machine(t, Capability{Status: Usable, Kind: KindTPM2}, true)
	dir := t.TempDir()
	if err := StoreRecoveryPhrase(dir, []byte(aPhrase)); err != nil {
		t.Fatal(err)
	}
	damaged := []byte(`{"v":1,"wrap":"fake","key":"!!","sealed":"","holder":"recovery-phrase"}`)
	if err := os.WriteFile(recoveryPhrasePath(dir), damaged, 0600); err != nil {
		t.Fatal(err)
	}
	if err := StoreRecoveryPhrase(dir, []byte(anotherPhrase)); !errors.Is(err, ErrADifferentPhraseIsHeld) {
		t.Fatalf("got %v", err)
	}
	if raw, _ := os.ReadFile(recoveryPhrasePath(dir)); !bytes.Equal(raw, damaged) {
		t.Fatal("overwritten")
	}
}
