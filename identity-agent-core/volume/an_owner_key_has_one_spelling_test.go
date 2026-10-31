package volume

import (
	"encoding/base64"
	"strings"
	"testing"
)

// An owner's sealing key is read in its one canonical string per spelling.
// 32 bytes in base64 leave 2 spare bits in the last character, and read
// leniently each key had 4 strings; a line break inside one was skipped.
func TestAnOwnerSealingKeyHasOneSpelling(t *testing.T) {
	_, pub := ownerKeypair(t)
	s := base64.StdEncoding.EncodeToString(pub) // 43 characters, then "="
	if got, err := ownerSealKey(s); err != nil || string(got) != string(pub) {
		t.Fatalf("the canonical key did not read: %v", err)
	}
	if _, err := ownerSealKey(" " + s + "\n"); err == nil {
		t.Fatal("a key with whitespace around it was read; it arrives over the wire and is not trimmed")
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	v := strings.IndexByte(alphabet, s[42])
	for name, other := range map[string]string{
		"spare bits": s[:42] + string(alphabet[v|1]) + "=",
		"line break": s[:20] + "\n" + s[20:],
		"short":      base64.StdEncoding.EncodeToString(pub[:31]),
	} {
		if _, err := ownerSealKey(other); err == nil {
			t.Errorf("%s: %q was read as an owner key", name, other)
		}
	}
}
