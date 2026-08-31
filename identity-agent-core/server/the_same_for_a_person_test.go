package server

import (
	"net/http"
	"testing"
)

// A person's Identity Agent recognises a machine exactly as an organisation's
// does, because it is the same mechanism and neither half knows the difference.
//
// Worth asserting rather than assuming. Nothing in the enrolment ceremony, the
// asset record or the caller resolver reads an entity type — the identity that
// delegates is whichever one this agent holds — so an individual controlling
// their own agent from a laptop is the same ceremony an organisation uses, and
// the controller does not need building twice. This test is what keeps that
// true if somebody later adds a check that assumes an organisation.
func TestAPersonsAgentRecognisesItsMachineTheSameWay(t *testing.T) {
	s := notifyTestServer(t)

	// The only thing that differs is whose root the delegation names, and it is
	// carried through untouched.
	const personAID = "EMACHINE-OF-A-PERSON"
	key := enrolledMachineOf(t, s, personAID, "EPERSON-ROOT")

	cc := s.resolveCaller(signedAs(t, key, personAID, http.MethodGet, "/api/identity"))
	if cc.CallerAID != personAID {
		t.Fatalf("a person's machine was not recognised: %q", cc.CallerAID)
	}
	if len(cc.DelegationChain) != 2 || cc.DelegationChain[1] != "EPERSON-ROOT" {
		t.Fatalf("the lineage does not reach the person: %v", cc.DelegationChain)
	}
	if len(cc.Scopes) != 0 {
		t.Fatalf("recognition granted scopes to a person's machine: %v", cc.Scopes)
	}
}
