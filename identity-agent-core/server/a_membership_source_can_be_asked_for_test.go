package server

import "testing"

type allAdmit struct{}

func (allAdmit) Admit(string, string) (bool, string) { return true, "" }

// An add-on that makes assets asks whether a membership source can be answered
// for here before it names one.
func TestAMembershipSourceCanBeAskedFor(t *testing.T) {
	if HasMembershipResolver("a-roster-nobody-registered") {
		t.Fatal("a source with no resolver is said to have one")
	}
	RegisterMembershipResolver("a-roster-somebody-registered", allAdmit{})
	defer delete(membershipResolvers, "a-roster-somebody-registered")
	if !HasMembershipResolver("a-roster-somebody-registered") {
		t.Fatal("a registered source is said not to have a resolver")
	}
}
