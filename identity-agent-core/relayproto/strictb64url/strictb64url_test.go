package strictb64url

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestTheCanonicalStringDecodes(t *testing.T) {
	want := bytes.Repeat([]byte{0xa5}, 64)
	got, err := Decode(base64.RawURLEncoding.EncodeToString(want))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("canonical value: %x, %v", got, err)
	}
}

func TestPaddingIsRefused(t *testing.T) {
	// "AA" is one zero byte; with padding it is the standard spelling.
	if _, err := Decode("AA"); err != nil {
		t.Fatalf("unpadded: %v", err)
	}
	if _, err := Decode("AA=="); err == nil {
		t.Error("padded value was read")
	}
}

func TestTheStandardAlphabetIsRefused(t *testing.T) {
	// 0xfb 0xff is "-_8" in base64url and "+/8" in the standard alphabet.
	if _, err := Decode("-_8"); err != nil {
		t.Fatalf("base64url: %v", err)
	}
	if _, err := Decode("+/8"); err == nil {
		t.Error("standard alphabet was read")
	}
}

func TestLineBreaksAreRefused(t *testing.T) {
	for _, s := range []string{"AAAA\nAAAA", "AAAA\r\nAAAA", "AAAA\n", "\rAAAA"} {
		if _, err := Decode(s); err == nil {
			t.Errorf("%q was read", s)
		}
	}
}

func TestSpareBitsAreRefused(t *testing.T) {
	// One byte is two characters and leaves 4 bits over: "AA" is the zero
	// byte, and "AB" through "AP" are the same byte with spare bits set.
	for _, s := range []string{"AB", "AP", "A_"} {
		if _, err := Decode(s); err == nil {
			t.Errorf("%q, with spare bits set, was read", s)
		}
	}
}

func TestIsAlphabet(t *testing.T) {
	if !IsAlphabet("Az09-_") || IsAlphabet("a=") || IsAlphabet("a+") || IsAlphabet("a/") || IsAlphabet("a\n") {
		t.Error("IsAlphabet drew the alphabet wrongly")
	}
}
