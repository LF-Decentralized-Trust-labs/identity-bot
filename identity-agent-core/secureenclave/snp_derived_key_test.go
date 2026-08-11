package secureenclave

import (
	"bytes"
	"testing"
)

// The firmware returns one key for one field selection, so everything that
// needs a distinct key gets it from here rather than from a second firmware
// call. These tests pin the properties that makes safe.

// Reproducibility is the whole mechanism. Nothing is stored: an instance
// encrypts with a key it asks for again on the next boot, and if the answer
// differed between boots the volume would be unopenable rather than protected.
func TestTheSamePurposeGivesTheSameKeyEveryTime(t *testing.T) {
	firmware := bytes.Repeat([]byte{0xA5}, DerivedKeySize)
	first := deriveForPurpose(firmware, "tenant-data")
	second := deriveForPurpose(firmware, "tenant-data")
	if !bytes.Equal(first, second) {
		t.Fatal("the same purpose produced two different keys, so a volume encrypted " +
			"on one boot could not be opened on the next")
	}
}

// Two uses must not share a key. Otherwise a weakness in one — a key recovered
// from a log, a scheme broken later — is a weakness in the other, and two
// things that should have been independent are not.
func TestDifferentPurposesGiveDifferentKeys(t *testing.T) {
	firmware := bytes.Repeat([]byte{0xA5}, DerivedKeySize)
	a := deriveForPurpose(firmware, "tenant-data")
	b := deriveForPurpose(firmware, "something-else")
	if bytes.Equal(a, b) {
		t.Fatal("two purposes share one key")
	}
	if bytes.Equal(a, firmware) {
		t.Fatal("a derived key is the firmware key itself, so the separation does nothing")
	}
}

// A different measurement means different software, which must not be handed
// the previous software's key. The firmware enforces this; this asserts the
// derivation does not undo it by ignoring what it was given.
func TestADifferentFirmwareKeyGivesADifferentDerivedKey(t *testing.T) {
	a := deriveForPurpose(bytes.Repeat([]byte{0x01}, DerivedKeySize), "tenant-data")
	b := deriveForPurpose(bytes.Repeat([]byte{0x02}, DerivedKeySize), "tenant-data")
	if bytes.Equal(a, b) {
		t.Fatal("two different firmware keys produced the same derived key, so the " +
			"binding to this software is not carried through")
	}
}

func TestADerivedKeyIsFullLengthAndNotZero(t *testing.T) {
	k := deriveForPurpose(bytes.Repeat([]byte{0xA5}, DerivedKeySize), "tenant-data")
	if len(k) != DerivedKeySize {
		t.Fatalf("key is %d bytes, want %d", len(k), DerivedKeySize)
	}
	if allZero(k) {
		t.Fatal("the derived key is all zeroes")
	}
}

// An empty purpose is still a purpose, and must not collide with a named one.
func TestAnEmptyPurposeDoesNotCollide(t *testing.T) {
	firmware := bytes.Repeat([]byte{0xA5}, DerivedKeySize)
	if bytes.Equal(deriveForPurpose(firmware, ""), deriveForPurpose(firmware, "tenant-data")) {
		t.Fatal("an unnamed purpose collides with a named one")
	}
}

// The purpose strings are an interface contract, not names.
//
// Every volume ever encrypted was encrypted with a key derived from one of
// these. Rename one in a refactor, correct its capitalisation, or "tidy" the
// version suffix, and every volume derived from it becomes unopenable — and the
// failure looks exactly like a measurement mismatch, so the first guess will be
// the wrong one.
//
// This test exists to fail loudly at the moment somebody changes one, rather
// than quietly in production months later. If a purpose genuinely must change,
// the old one has to keep working for volumes already sealed under it, which
// means adding a new purpose rather than editing this list.
func TestThePurposeStringsHaveNotChanged(t *testing.T) {
	firmware := bytes.Repeat([]byte{0x5A}, DerivedKeySize)

	// Recorded outputs. Regenerating these to make the test pass is the exact
	// mistake this guards against.
	for purpose, want := range map[string]string{
		"tenant-data-volume-v1": "50405d287148970673a2bd43aa7ede67f258282b8a5da193f59256cb52b470e7",
	} {
		got := hexOf(deriveForPurpose(firmware, purpose))
		if got != want {
			t.Errorf("the key derived for %q changed.\n got: %s\nwant: %s\n\n"+
				"If this was a rename or a tidy-up, revert it: every volume sealed under "+
				"the old purpose becomes unopenable, and the failure looks like a "+
				"measurement mismatch rather than like this. If the change is genuinely "+
				"needed, add a new purpose and keep this one working.", purpose, got, want)
		}
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, digits[x>>4], digits[x&0x0f])
	}
	return string(out)
}
