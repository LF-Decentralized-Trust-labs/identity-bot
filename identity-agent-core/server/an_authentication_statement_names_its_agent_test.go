package server

import (
	"testing"
	"time"

	"identity-agent-core/authprovider"
	"identity-agent-core/login"
	"identity-agent-core/store"
)

// The exact text the device holding the root key signs. Published so another
// implementation of the device, or of an Identity Agent, can check itself
// against it.
func TestTheAuthLevelStatementHasOneFixedForm(t *testing.T) {
	at := time.Date(2026, 11, 11, 9, 30, 0, 0, time.UTC)
	got := canonicalAuthLevelStatement("EAgent", "BController", authprovider.LevelAuthenticated, at, 80)
	want := "IA-AUTH-LEVEL-V2\nEAgent\nBController\nauthenticated\n2026-11-11T09:30:00Z\n80"
	if got != want {
		t.Fatalf("statement = %q, want %q", got, want)
	}
}

// A statement made for one Identity Agent is worth nothing at another, even
// when the same device holds both identities' root keys and the same machine
// carries it. Fails if the agent's identifier is left out of the statement.
func TestAStatementForAnotherAgentIsNotBelieved(t *testing.T) {
	s := agentWithNoIdentity(t)
	aid, _ := anAuthorisedMachine(t, s, GradeEnrolled)
	seed := rootDeviceSeeds[t.Name()]
	if err := s.DataStore.SaveIdentity(store.IdentityState{AID: "EThisAgent"}); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()

	forThisAgent := remote("GET", "/api/profile", "")
	forThisAgent.Header.Set(headerControllerAuthLevel, string(authprovider.LevelHigh))
	forThisAgent.Header.Set(headerControllerAuthAt, at.Format(time.RFC3339))
	forThisAgent.Header.Set(headerControllerAuthScore, "90")
	forThisAgent.Header.Set(headerAuthLevelVouchedBy, theRootDeviceVouches(t, aid, authprovider.LevelHigh, at, 90))
	if got := s.theAuthenticationSomebodyVouchedFor(forThisAgent, aid, at); !got.Measured {
		t.Fatalf("a statement for this agent was refused: %s", got.Why)
	}

	other, err := login.SignString(
		canonicalAuthLevelStatement("EAnotherAgent", aid, authprovider.LevelHigh, at, 90), seed)
	if err != nil {
		t.Fatal(err)
	}
	forAnother := remote("GET", "/api/profile", "")
	forAnother.Header.Set(headerControllerAuthLevel, string(authprovider.LevelHigh))
	forAnother.Header.Set(headerControllerAuthAt, at.Format(time.RFC3339))
	forAnother.Header.Set(headerControllerAuthScore, "90")
	forAnother.Header.Set(headerAuthLevelVouchedBy, other)
	if got := s.theAuthenticationSomebodyVouchedFor(forAnother, aid, at); got.Measured {
		t.Fatal("a statement made for a different Identity Agent was believed")
	}
}
