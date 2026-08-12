package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Reading back who agreed to own this agent.
//
// The case that matters is the one before an identity exists: an organisation
// about to be founded on a machine has to hand that machine its owner, and at
// that moment there is no key event log to read an owner out of. This was
// recorded and then unreadable, so the founding could not name the person who
// had just agreed to it.

func TestAnAgentReportsTheOwnerItWasSealedTo(t *testing.T) {
	s := ownerServer(t, "EOWNERAID")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/owners/authority", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	s.handleOwnerAuthority(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("reading the owner failed: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Owner *struct {
			AID       string `json:"aid"`
			PublicKey string `json:"public_key"`
		} `json:"owner"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Owner == nil || body.Owner.AID != "EOWNERAID" {
		t.Fatal("the agent did not report the owner it was sealed to, so nothing " +
			"can name that owner when founding an organisation on a machine")
	}
	if body.Owner.PublicKey == "" {
		t.Error("no verification key, so the organisation could not check its owner's signature")
	}
}

// An agent nobody has claimed is an ordinary state, and a screen has to be able
// to tell it apart from a failure.
func TestAnUnclaimedAgentSaysSoRatherThanFailing(t *testing.T) {
	s := ownerServer(t, "")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/owners/authority", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	s.handleOwnerAuthority(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("an unclaimed agent reported an error instead of an answer: %d", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "null") {
		t.Errorf("an unclaimed agent should report no owner, got: %s", body)
	}
}
