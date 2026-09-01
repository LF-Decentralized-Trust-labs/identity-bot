package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A machine finds out it was approved by asking, not by being told.
//
// There is no channel from an agent back to a machine it has never spoken to,
// and building one would mean a push path and a way for a stranger to be told
// things. It does not need one: a request signed by a machine nobody authorised
// is refused, and the same request after the owner approves is served. So the
// ceremony completes without anything being pushed anywhere.
func TestAMachineLearnsItWasApprovedByAsking(t *testing.T) {
	s := agentWithNoIdentity(t)
	ownerSeedForTest(t, s)
	r := s.buildRouter("")

	// The machine as it is before anybody approves it: it has its own key and
	// nothing else.
	me := grantFor(42, GradeEnrolled)
	seed := seedForGrant(42)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, me.ControllerAID, "GET", "/api/controller/agent",
		"", seed, "", time.Time{}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a machine nobody authorised was told about this identity: %d %s",
			w.Code, w.Body.String())
	}

	// The owner approves it, on the device holding the key.
	me.Label = "the laptop in the study"
	if _, err := s.controllers().Grant(me, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	// The same question, asked again. This is the whole mechanism.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, me.ControllerAID, "GET", "/api/controller/agent",
		"", seed, "", time.Time{}))
	if w.Code != http.StatusOK {
		t.Fatalf("an approved machine could not find out: %d %s", w.Code, w.Body.String())
	}

	var got whoThisAgentIs
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.YourLabel != "the laptop in the study" {
		t.Errorf("it was not told what the owner called it: %+v", got)
	}
	if got.YourGrade != GradeEnrolled {
		t.Errorf("it was not told what it was approved as: %+v", got)
	}
}

// It is told WHICH identity it now acts for, and that is the point of the route.
//
// An address is not an identity: a relay allocation can be reassigned, and a
// machine answering where the agent used to be is not the agent. A controller
// that recorded only where to go would trust whatever answered there next time.
func TestAnApprovedMachineIsToldWhichIdentityItActsFor(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	ownerSeedForTest(t, s)

	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil || identity.AID == "" {
		t.Skip("this fixture has no identity to be told about")
	}

	me := grantFor(43, GradeScoped)
	me.Label = "a computer in the library"
	if _, gerr := s.controllers().Grant(me, time.Now().UTC()); gerr != nil {
		t.Fatal(gerr)
	}
	r := s.buildRouter("")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, me.ControllerAID, "GET", "/api/controller/agent",
		"", seedForGrant(43), "", time.Time{}))
	if w.Code != http.StatusOK {
		t.Fatalf("approved machine refused: %d %s", w.Code, w.Body.String())
	}

	var got whoThisAgentIs
	if uerr := json.Unmarshal(w.Body.Bytes(), &got); uerr != nil {
		t.Fatal(uerr)
	}
	if got.AID != identity.AID {
		t.Fatalf("it was not told which identity it acts for: got %q, want %q",
			got.AID, identity.AID)
	}
	// A borrowed machine is told when its authorisation stops, so it can say so
	// rather than simply failing later.
	if got.YourAuthorisationEnds == nil {
		t.Error("a borrowed machine was not told when it stops")
	}
}
