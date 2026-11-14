package fingerprint

import (
	"bytes"
	"testing"
)

// The bytes of version 1 are pinned here, so a change to the construction
// cannot pass unnoticed while its callers' vectors happen to move with it.
// pinnedYes was computed outside Go, from the construction ADR-067 states:
// Blake3-256 of "IA-FINGERPRINT-V1", 0x0010, sixteen 0x01 bytes and "yes",
// written as a CESR digest.
const pinnedYes = "EJh9zP6S5tx5Num0evHlsTpvNCufNORxZfqq8JDL3i1a"

func TestTheFirstVersionIsPinned(t *testing.T) {
	salt := bytes.Repeat([]byte{0x01}, MinSalt)
	got, err := Of(salt, []byte("yes"))
	if err != nil {
		t.Fatal(err)
	}
	if got != pinnedYes {
		t.Fatalf("the version 1 fingerprint of \"yes\" changed: got %s, pinned %s", got, pinnedYes)
	}
}

func TestASaltOutsideItsBoundsIsRefused(t *testing.T) {
	for _, n := range []int{0, MinSalt - 1, MaxSalt + 1} {
		if _, err := Of(make([]byte, n), []byte("w")); err == nil {
			t.Errorf("a salt of %d bytes was taken", n)
		}
	}
	for _, n := range []int{MinSalt, MaxSalt} {
		if _, err := Of(make([]byte, n), []byte("w")); err != nil {
			t.Errorf("a salt of %d bytes was refused: %v", n, err)
		}
	}
}

// The salt's length is part of what is digested, so moving a byte from the
// salt to the words (or back) gives a different fingerprint.
func TestMovingAByteBetweenSaltAndWordsChangesTheFingerprint(t *testing.T) {
	salt := bytes.Repeat([]byte{'s'}, MinSalt+1)
	a, err := Of(salt, []byte("words"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Of(salt[:MinSalt], append([]byte{'s'}, "words"...))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("a byte moved from the salt to the words left the fingerprint the same")
	}
}

func TestEachSaltIsFreshAndTheShortestAllowed(t *testing.T) {
	a, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != MinSalt || bytes.Equal(a, b) {
		t.Fatalf("salts of %d bytes, equal: %v", len(a), bytes.Equal(a, b))
	}
}
