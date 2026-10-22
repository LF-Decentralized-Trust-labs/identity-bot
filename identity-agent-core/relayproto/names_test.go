package relayproto

import "testing"

func TestTheNameRule(t *testing.T) {
	for _, ok := range []string{"abc", "acme-labs", "a1b", "x2345678901234567890123456789012"[:32]} {
		if !ValidName(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "ab", "Acme", "-acme", "acme-", "ac--me", "xn--acme", "acme_labs", "acme.labs",
		"a23456789012345678901234567890123", "zoë"} {
		if ValidName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
