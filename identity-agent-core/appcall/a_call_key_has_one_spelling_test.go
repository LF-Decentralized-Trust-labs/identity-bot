package appcall

import (
	"strings"
	"testing"
)

// The call key is read exactly as EncodeKey writes it. Read leniently, with
// spaces trimmed and spare bits ignored, one key had several strings.
func TestACallKeyHasOneSpelling(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	s := EncodeKey(k)
	if got, err := DecodeKey(s); err != nil || string(got) != string(k) {
		t.Fatalf("the key did not read back: %v", err)
	}
	others := map[string]string{
		"padded":     s + strings.Repeat("=", (4-len(s)%4)%4),
		"spaces":     " " + s + "\n",
		"line break": s[:10] + "\n" + s[10:],
	}
	if len(s)%4 != 0 {
		last := len(s) - 1
		v := strings.IndexByte(alphabet, s[last])
		others["spare bits"] = s[:last] + string(alphabet[v|1])
	}
	for name, other := range others {
		if other == s {
			continue
		}
		if _, err := DecodeKey(other); err == nil {
			t.Errorf("%s: %q was read as the call key", name, other)
		}
	}
}
