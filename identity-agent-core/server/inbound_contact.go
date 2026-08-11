package server

import (
	"encoding/json"
	"fmt"
	"log"

	"identity-agent-core/didcomm"
	"identity-agent-core/store"
)

// An introduction or an acceptance arriving inside an envelope.
//
// These are the two highest-traffic things agents say to each other, and they
// went in the clear to an endpoint that took the sender's identifier from the
// request body. Signing them closed the immediate hole. Moving them inside the
// envelope removes the question entirely: the sender is established by the
// envelope, so there is no identifier to check, no signature to verify, and
// nothing left to forge.
//
// The plaintext endpoint stays for now, and stays signed, because an agent that
// has not moved across yet still uses it and taking it away would silently cut
// them off. Retiring it is a separate step, taken once the envelope path is
// carrying the traffic.
//
// One thing does not change: an introduction still has to establish who the
// other party is, because being able to open an envelope to us says a
// relationship exists and says nothing about whose. That work belongs to the
// contact layer and is unchanged — this only replaces how the message arrived.

func init() {
	registerInboundAction(contactRequest{})
	registerInboundAction(contactAck{})
}

// contactExchange is what one agent tells another when introducing itself or
// agreeing to a relationship.
//
// No sender field. Who this is from is the envelope's answer, and a body that
// could name somebody would be a second answer to a settled question.
type contactExchange struct {
	Kind        string       `json:"kind"` // "introduction" | "acceptance"
	SenderOOBI  string       `json:"sender_oobi,omitempty"`
	SenderAlias string       `json:"sender_alias,omitempty"`
	SenderJCard *store.JCard `json:"sender_jcard,omitempty"`
	SenderPhoto string       `json:"sender_photo,omitempty"`
}

type contactRequest struct{}

func (contactRequest) Type() string { return didcomm.TypeContactRequest }

func (contactRequest) Perform(s *CoreServer, in InboundMessage) error {
	var body contactExchange
	if err := json.Unmarshal(in.Body, &body); err != nil {
		return fmt.Errorf("the introduction could not be read: %w", err)
	}
	if body.SenderOOBI == "" {
		return fmt.Errorf("an introduction has to say where to find the sender's key history")
	}

	// Establish who they are from their own key history, which is the part the
	// envelope cannot do for us: it proves somebody holds this identity's
	// encryption keys, not that the identity is what it claims about itself.
	contact, _, err := s.EnsureKeriContact(body.SenderOOBI)
	if err != nil {
		return fmt.Errorf("could not establish who %s is: %w", in.FromAID, err)
	}
	if contact.AID != in.FromAID {
		// The address they gave belongs to somebody else. Refused rather than
		// reconciled — an introduction that points at a different identity than
		// the one that sent it is either broken or an attempt to have us record
		// a stranger under a name we already trust.
		return fmt.Errorf("the envelope came from %s but the address given belongs to %s",
			in.FromAID, contact.AID)
	}

	if body.SenderAlias != "" && contact.Alias == "" {
		contact.Alias = body.SenderAlias
	}
	if body.SenderJCard != nil {
		contact.JCard = body.SenderJCard
	}
	if contact.Status == "pending_outbound" {
		// We had already reached out to them, and now they have reached back.
		contact.Status = "accepted"
	}
	if err := s.DataStore.SaveContact(*contact); err != nil {
		return fmt.Errorf("could not record the introduction: %w", err)
	}

	s.EventHub.Broadcast(AgentEvent{
		Type:    "contact_introduction",
		Payload: map[string]interface{}{"sender_aid": in.FromAID, "sender_alias": contact.Alias},
	})
	log.Printf("[contacts] introduction from %s (%s)", in.FromAID, contact.Status)
	return nil
}

type contactAck struct{}

func (contactAck) Type() string { return didcomm.TypeAck }

func (contactAck) Perform(s *CoreServer, in InboundMessage) error {
	contact, err := s.DataStore.GetContact(in.FromAID)
	if err != nil || contact == nil {
		return fmt.Errorf("%s accepted a relationship this agent has no record of starting", in.FromAID)
	}
	if contact.Status != "pending_outbound" && contact.Status != "pending_inbound" {
		// Nothing to move. Not an error: an acceptance arriving twice, or after
		// the relationship is already settled, is ordinary.
		return nil
	}
	contact.Status = "accepted"
	if err := s.DataStore.SaveContact(*contact); err != nil {
		return fmt.Errorf("could not record the acceptance: %w", err)
	}
	s.EventHub.Broadcast(AgentEvent{
		Type:    "contact_accepted",
		Payload: map[string]interface{}{"sender_aid": in.FromAID, "sender_alias": contact.Alias},
	})
	log.Printf("[contacts] %s accepted", in.FromAID)
	return nil
}

// SendIntroduction introduces this agent to another, inside an envelope.
func (s *CoreServer) SendIntroduction(fromAID, toAID, ourOOBI, ourAlias string, jcard *store.JCard) error {
	body, err := json.Marshal(contactExchange{
		Kind: "introduction", SenderOOBI: ourOOBI, SenderAlias: ourAlias, SenderJCard: jcard,
	})
	if err != nil {
		return err
	}
	_, status, err := s.SendDIDCommMessage(fromAID, toAID, didcomm.TypeContactRequest, body)
	if err != nil {
		return fmt.Errorf("could not introduce ourselves to %s: %w", toAID, err)
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("%s refused the introduction (%d)", toAID, status)
	}
	return nil
}

// SendAcceptance tells another agent this relationship is agreed.
func (s *CoreServer) SendAcceptance(fromAID, toAID string) error {
	body, _ := json.Marshal(contactExchange{Kind: "acceptance"})
	_, status, err := s.SendDIDCommMessage(fromAID, toAID, didcomm.TypeAck, body)
	if err != nil {
		return fmt.Errorf("could not tell %s we accepted: %w", toAID, err)
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("%s refused the acceptance (%d)", toAID, status)
	}
	return nil
}
