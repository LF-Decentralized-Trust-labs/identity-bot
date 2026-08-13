package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The screen needs somewhere to point a phone at, and only the agent knows it.
//
// The screen reaches this agent over loopback, and loopback is the one address
// that is useless to another device — a code carrying it would send the phone
// back to itself. So the address comes from the agent, which knows how it is
// actually reached.
func TestOfferingThisComputerSaysWhereToReachIt(t *testing.T) {
	resetLocalPairingOfferForTest()
	resetExpectedClaimForTest()
	s := agentWithNoIdentity(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/pairing/offer-this-computer", nil)
	req.RemoteAddr = "127.0.0.1:5050"
	req.Host = "192.168.0.24:5050"
	s.handleOfferThisComputer(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("offer failed: %s", rec.Body.String())
	}

	var body struct {
		Code    string `json:"code"`
		Address string `json:"address"`
	}
	json.NewDecoder(rec.Body).Decode(&body)
	if body.Address == "" {
		t.Fatal("the offer says nothing about where this computer is, so a code shown on " +
			"screen could only ever be typed and never scanned")
	}
	if body.Code == "" {
		t.Fatal("no code")
	}
}

// An agent that has not wired its endpoint service yet must still answer.
//
// This runs on a freshly installed machine before onboarding, which is exactly
// when that service may not exist. Reaching through it turned "I do not know my
// address" into a crash that took the whole request down.
func TestAFreshAgentWithNoEndpointServiceStillOffersItself(t *testing.T) {
	resetLocalPairingOfferForTest()
	resetExpectedClaimForTest()
	s := agentWithNoIdentity(t)
	s.EndpointService = nil

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/pairing/offer-this-computer", nil)
	req.RemoteAddr = "127.0.0.1:5050"
	s.handleOfferThisComputer(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("a fresh agent could not offer itself: %d %s", rec.Code, rec.Body.String())
	}
}
