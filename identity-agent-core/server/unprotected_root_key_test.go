package server

import "testing"

// The switch has to be unreachable by accident. Anything other than an explicit
// "1" leaves the rule in force, so a stray value, a shell that exports empty
// variables, or somebody setting it to "false" does not quietly open the door.
func TestOnlyAnExplicitValueLiftsTheRule(t *testing.T) {
	for _, v := range []string{"", "0", "false", "no", "true", "yes", "2", " "} {
		t.Setenv(envAllowUnprotectedRootKey, v)
		if allowUnprotectedRootKey() {
			t.Errorf("%q lifted the hardware requirement", v)
		}
	}
	t.Setenv(envAllowUnprotectedRootKey, "1")
	if !allowUnprotectedRootKey() {
		t.Error("the switch does not work when set as documented")
	}
	// Surrounding whitespace is a config-file accident, not a different answer.
	t.Setenv(envAllowUnprotectedRootKey, " 1 ")
	if !allowUnprotectedRootKey() {
		t.Error("a value with whitespace around it was treated as unset")
	}
}

// Whether the root is protected must be answerable by anything that needs to
// record or display it — an arrangement that lives only in a log is one nobody
// finds out about.
func TestTheArrangementIsReportable(t *testing.T) {
	t.Setenv(envAllowUnprotectedRootKey, "1")
	if !RootKeyIsUnprotected() {
		t.Error("an agent holding an unprotected root key does not report it")
	}
	t.Setenv(envAllowUnprotectedRootKey, "")
	if RootKeyIsUnprotected() {
		t.Error("an agent reports an unprotected root key when the rule is in force")
	}
}
