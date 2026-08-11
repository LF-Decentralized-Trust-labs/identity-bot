package server

import (
	"encoding/json"
	"strings"
	"testing"

	"identity-agent-core/store"
)

// An acceptance moves a relationship, and who sent it is the envelope's answer.
// The plaintext version took an identifier from the body, which is what let
// anybody move anybody's contact.
func TestAnAcceptanceInAnEnvelopeNeedsNoIdentifierInTheBody(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	_ = s.DataStore.SaveContact(store.ContactRecord{AID: "ETHEIRS", Status: "pending_outbound"})

	body, _ := json.Marshal(contactExchange{Kind: "acceptance"})
	if err := (contactAck{}).Perform(s, InboundMessage{FromAID: "ETHEIRS", Body: body}); err != nil {
		t.Fatalf("a genuine acceptance was refused: %v", err)
	}
	after, _ := s.DataStore.GetContact("ETHEIRS")
	if after.Status != "accepted" {
		t.Fatalf("status is %q, want accepted", after.Status)
	}
}

// An acceptance for a relationship this agent never started has nothing to move.
func TestAnAcceptanceForARelationshipWeNeverStartedIsRefused(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	body, _ := json.Marshal(contactExchange{Kind: "acceptance"})
	err := (contactAck{}).Perform(s, InboundMessage{FromAID: "ENOBODY", Body: body})
	if err == nil {
		t.Fatal("an acceptance from a stranger was acted on")
	}
	if !strings.Contains(err.Error(), "no record") {
		t.Errorf("the reason is unclear: %v", err)
	}
}

// Arriving twice, or after the relationship is settled, is ordinary and must not
// be reported as a failure.
func TestARepeatedAcceptanceIsNotAnError(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	_ = s.DataStore.SaveContact(store.ContactRecord{AID: "ETHEIRS", Status: "accepted"})
	body, _ := json.Marshal(contactExchange{Kind: "acceptance"})
	if err := (contactAck{}).Perform(s, InboundMessage{FromAID: "ETHEIRS", Body: body}); err != nil {
		t.Fatalf("a repeated acceptance was treated as a failure: %v", err)
	}
}

// An introduction has to establish who sent it from their own key history. The
// envelope proves somebody holds this identity's encryption keys; it says
// nothing about what that identity claims to be.
func TestAnIntroductionThatCannotBeEstablishedIsRefused(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	body, _ := json.Marshal(contactExchange{
		Kind: "introduction", SenderOOBI: "https://example.invalid/oobi",
	})
	if err := (contactRequest{}).Perform(s, InboundMessage{FromAID: "ETHEIRS", Body: body}); err == nil {
		t.Fatal("an introduction was accepted without establishing who sent it")
	}
}

// An introduction that says nothing about where to find the sender cannot
// establish them, so it is refused rather than recorded on their say-so.
func TestAnIntroductionWithNoAddressIsRefused(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	body, _ := json.Marshal(contactExchange{Kind: "introduction"})
	err := (contactRequest{}).Perform(s, InboundMessage{FromAID: "ETHEIRS", Body: body})
	if err == nil {
		t.Fatal("an introduction with no address was accepted")
	}
	if !strings.Contains(err.Error(), "key history") {
		t.Errorf("the reason is unclear: %v", err)
	}
}

// Both actions have to be reachable, or they are handlers nothing can deliver to.
func TestTheContactActionsAreDeliverable(t *testing.T) {
	for _, want := range []string{(contactRequest{}).Type(), (contactAck{}).Type()} {
		a, ok := lookupInboundAction(want)
		if !ok {
			t.Errorf("nothing is registered for %q", want)
			continue
		}
		if !knownEnvelopeType(a.Type()) {
			t.Errorf("%q would be rejected by the envelope layer, so nothing could deliver it", want)
		}
	}
}
