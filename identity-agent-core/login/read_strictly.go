package login

import (
	"fmt"
	"regexp"
	"strconv"
	"time"

	"identity-agent-core/internal/strictjson"
)

// ReadAssertion reads a login assertion only if every verifier would read
// the same one: each key exactly a field's name and named once, the text
// valid, nothing unknown (strictjson). encoding/json alone matches names
// ignoring case, so {"nonce":"n","Nonce":"x"} was read here with the nonce
// "x" and by a verifier in another language with "n" — one signature, two
// assertions.
func ReadAssertion(data []byte) (Assertion, error) {
	var a Assertion
	if err := strictjson.Decode(data, &a); err != nil {
		return Assertion{}, fmt.Errorf("the assertion cannot be read: %w", err)
	}
	return a, nil
}

// ReadChallengeBundle reads a site's challenge by the same rules as
// ReadAssertion.
func ReadChallengeBundle(data []byte) (ChallengeBundle, error) {
	var b ChallengeBundle
	if err := strictjson.Decode(data, &b); err != nil {
		return ChallengeBundle{}, fmt.Errorf("the challenge cannot be read: %w", err)
	}
	return b, nil
}

// rfc3339 is RFC 3339's date-time exactly: a dot before any fraction, and an
// offset of Z or ±hh:mm. time.Parse also takes a comma, an offset hour of 24
// and an offset minute of 60, which a verifier in another language refuses.
var rfc3339 = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-](\d{2}):(\d{2}))$`)

// parseRFC3339 reads a time a login carries (its dt, a challenge's expiry)
// only if it is RFC 3339 exactly and names a real instant: 2026-02-30 and
// 24:00 are refused, by time.Parse.
func parseRFC3339(s string) (time.Time, error) {
	m := rfc3339.FindStringSubmatch(s)
	if m == nil {
		return time.Time{}, fmt.Errorf("%q is not an RFC 3339 time", s)
	}
	if m[3] != "" {
		hh, _ := strconv.Atoi(m[3])
		mm, _ := strconv.Atoi(m[4])
		if hh > 23 || mm > 59 {
			return time.Time{}, fmt.Errorf("%q has an offset that is not a time of day", s)
		}
	}
	return time.Parse(time.RFC3339, s)
}
