package relayproto

import (
	"regexp"
	"strings"
	"testing"
)

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

// The pattern and limits a screen is given are the ones ValidName applies: the
// shortest and longest names the limits allow are accepted, one either side is
// not, and the forbidden sequence is refused though the pattern alone allows it.
func TestTheExportedRuleIsTheRuleApplied(t *testing.T) {
	at := func(n int) string { return "a" + strings.Repeat("b", n-1) }
	if !ValidName(at(NameMinLen)) || !ValidName(at(NameMaxLen)) {
		t.Error("a name at a limit is refused")
	}
	if ValidName(at(NameMinLen-1)) || ValidName(at(NameMaxLen+1)) {
		t.Error("a name past a limit is accepted")
	}
	if !regexp.MustCompile(NamePattern).MatchString("ac" + NameForbids + "me") {
		t.Error("the pattern is expected to allow the forbidden sequence; ValidName refuses it")
	}
	if ValidName("ac" + NameForbids + "me") {
		t.Error("the forbidden sequence is accepted")
	}
}
