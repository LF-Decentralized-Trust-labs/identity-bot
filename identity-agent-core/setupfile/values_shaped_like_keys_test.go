package setupfile

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// The reader refuses a file that holds something shaped like a key, so its
// tests need text shaped like the keys of real services. Every such value is
// made up, and each is built here, at run time, from parts split inside its
// recognisable beginning and inside the rest, so that no source file holds one
// whole. A published vector whose file holds one carries the file's bytes in
// hexadecimal (file_hex), so the vectors hold none as text either.

// joined is the one way these values are built.
func joined(parts ...string) string { return strings.Join(parts, "") }

// shapedLikeAKey are the values, by what each is shaped like. None is a key.
var shapedLikeAKey = map[string]string{
	"a private key block":     joined("-----BEGIN PRIV", "ATE KEY-----\nMC4CAQAw", "BQYDK2VwBCIEIA\n-----END PRIVATE KEY-----"),
	"a PGP private key block": joined("-----BEGIN PGP PRIV", "ATE KEY BLOCK-----"),
	// sk- and the part after its last - or _: 20 or more letters and digits,
	// holding a digit, is a key; without a digit, or shorter, it is not.
	"sk- and 32 letters and digits":         joined("s", "k-", strings.Repeat("a1B2", 4), strings.Repeat("a1B2", 4)),
	"sk- and 32 hexadecimal digits":         joined("s", "k-", strings.Repeat("0f1e2d3c", 2), strings.Repeat("0f1e2d3c", 2)),
	"sk- after a route, and 64 hexadecimal": joined("sk-o", "r-v1-", strings.Repeat("0f1e2d3c", 4), strings.Repeat("0f1e2d3c", 4)),
	"sk- and 24 letters":                    joined("s", "k-", strings.Repeat("a", 12), strings.Repeat("a", 12)),
	"sk- and 23 letters and a digit":        joined("s", "k-", strings.Repeat("a", 12), strings.Repeat("a", 11), "1"),
	"sk- and 20 letters and a dash":         joined("s", "k-", strings.Repeat("a", 10), strings.Repeat("a", 10), "-"),
	"a mail service key":                    joined("S", "G.", strings.Repeat("a1B2", 5), "ab.", strings.Repeat("a1B2", 5), strings.Repeat("a1B2", 5), "abc"),
	"a live key":                            joined("sk_li", "ve_", strings.Repeat("a1B2", 3), strings.Repeat("a1B2", 3)),
	"a restricted live key":                 joined("rk_li", "ve_", strings.Repeat("a1B2", 3), strings.Repeat("a1B2", 3)),
	"a GitHub token":                        joined("gh", "p_", strings.Repeat("a1", 6), strings.Repeat("a1", 6)),
	"a GitLab token":                        joined("gl", "pat-", strings.Repeat("a1B2", 2), strings.Repeat("a1B2", 3)),
	"an npm token":                          joined("np", "m_", strings.Repeat("a1B2", 4), strings.Repeat("a1B2", 5)),
	"an age key":                            joined("AGE-SECRET-", "KEY-1", strings.Repeat("QPZRY9X8", 3), strings.Repeat("QPZRY9X8", 4)),
	"a JSON Web Token":                      joined("ey", "JhbGciOiJIUzI1NiJ9.", "ey", "JzdWIiOiIxMjM0NTY3ODkwIn0.abc"),
	"an access key":                         joined("AK", "IA", "ABCDEFGH", "IJKLMNOP"),
	"an access key split by a joiner":       joined("AK", "IA1234‍", "567890ABCDEF"),
	"an access key split by a soft hyphen":  joined("AK", "IAIOSF­", "ODNN7EXAMPLE"),
	"an access key split by two unseen":     joined("AK", "IAIOSF‌", "ODNN7️EXAMPLE"),
	"sk- with a project, split by a joiner": joined("sk-pr", "oj-abcdefghij1‍", "2klmnopqrstuvwxyz"),
}

// keyShaped is the value the table holds under name.
func keyShaped(name string) string {
	v, ok := shapedLikeAKey[name]
	if !ok {
		panic("no value shaped like a key is named " + name)
	}
	return v
}

// holdsKeyShapedText is whether b holds any of the values above, as it is or
// as it is written in a JSON string.
func holdsKeyShapedText(b []byte) bool {
	for _, v := range shapedLikeAKey {
		quoted, _ := json.Marshal(v)
		if bytes.Contains(b, []byte(v)) || bytes.Contains(b, quoted[1:len(quoted)-1]) {
			return true
		}
	}
	return false
}

func TestEveryValueShapedLikeAKeyIsJudgedAsItsShapeSays(t *testing.T) {
	notKeys := map[string]bool{"sk- and 24 letters": true, "sk- and 20 letters and a dash": true}
	for name, v := range shapedLikeAKey {
		got := shapeOf(v)
		switch {
		case notKeys[name] && got == secretShape:
			t.Errorf("%s is judged shaped like a key", name)
		case !notKeys[name] && got != secretShape:
			t.Errorf("%s is shaped %d, not like a key", name, got)
		}
	}
}
