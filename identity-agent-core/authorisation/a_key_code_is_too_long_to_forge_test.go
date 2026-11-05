package authorisation

import (
	"regexp"
	"strings"
	"testing"

	"github.com/zeebo/blake3"
)

// Two known keys are pinned to their codes (checked against an independent
// Blake3 implementation, not only this one). A change to the domain string, the
// alphabet or the grouping changes these, and every code a person has already
// compared with changes with it.
func TestKeyFingerprintPinsKnownKeys(t *testing.T) {
	for key, want := range map[string]string{
		"DAtHgj5xCV3Vm-eKwnHFdu84n4e2RWGrB8-aTrzQLSBB": "M8PN-ME83-7RPK-D6FF",
		"DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx": "CAJR-NJXE-0370-4RZR",
	} {
		if got := KeyFingerprint(key); got != want {
			t.Errorf("KeyFingerprint(%s) = %s, want %s", key, got, want)
		}
	}
}

var keyCodeShape = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$`)

func TestKeyFingerprintShapeAndWhitespace(t *testing.T) {
	k := "DAtHgj5xCV3Vm-eKwnHFdu84n4e2RWGrB8-aTrzQLSBB"
	got := KeyFingerprint(k)
	if !keyCodeShape.MatchString(got) {
		t.Fatalf("%q is not four groups of four Crockford characters", got)
	}
	if KeyFingerprint("  "+k+"\n") != got {
		t.Error("whitespace around the key changed its code")
	}
	if KeyFingerprint("") != "" {
		t.Error("no key must give no code")
	}
	if strings.ToUpper(got) != got {
		t.Error("the code is upper case")
	}
}

// Keys that differ in one bit give different codes, for every bit of a key.
func TestKeyFingerprintOneBitApart(t *testing.T) {
	base := []byte("DAtHgj5xCV3Vm-eKwnHFdu84n4e2RWGrB8-aTrzQLSBB")
	seen := map[string]int{KeyFingerprint(string(base)): -1}
	for i := 0; i < len(base)*8; i++ {
		k := append([]byte(nil), base...)
		k[i/8] ^= 1 << (i % 8)
		code := KeyFingerprint(string(k))
		if j, dup := seen[code]; dup {
			t.Fatalf("flipping bit %d gives the code of %d: %s", i, j, code)
		}
		seen[code] = i
	}
}

// The code is the first 80 bits of the digest, so all 16 characters vary
// (the first character is not limited to a few values).
func TestKeyFingerprintUsesAllEightyBits(t *testing.T) {
	first := map[byte]bool{}
	for i := 0; i < 2000; i++ {
		sum := blake3.Sum256([]byte{byte(i), byte(i >> 8)})
		first[KeyFingerprint(string(sum[:8]))[0]] = true
	}
	if len(first) < 30 {
		t.Errorf("first character took only %d of 32 values", len(first))
	}
}
