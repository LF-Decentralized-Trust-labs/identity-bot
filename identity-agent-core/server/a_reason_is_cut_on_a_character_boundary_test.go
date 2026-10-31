package server

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// A reason or work item longer than the log keeps is cut on a character
// boundary. Cut inside a multi-byte character, the value ended in a byte that
// is not UTF-8.
func TestAReasonIsCutOnACharacterBoundary(t *testing.T) {
	for _, tail := range []string{"é", "€", "𝄞"} {
		v := strings.Repeat("a", maxWhyLen-1) + tail
		got := clampWhy(v)
		if !utf8.ValidString(got) || len(got) > maxWhyLen || got != strings.Repeat("a", maxWhyLen-1) {
			t.Fatalf("cut before %q: %d bytes, valid %v", tail, len(got), utf8.ValidString(got))
		}
	}
	if got := clampWhy(strings.Repeat("b", maxWhyLen+10)); len(got) != maxWhyLen {
		t.Fatalf("an ASCII reason is cut at %d bytes, not %d", len(got), maxWhyLen)
	}
}
