package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"identity-agent-core/agentpeer"
	"identity-agent-core/didcomm"
)

// SendAgentPeerMessage sends a message from an AI agent this Identity Agent
// holds to an AI agent a contact's Identity Agent holds (ADR-085): this Identity
// Agent signs the statement with its own messaging keys and carries it, with
// the words, inside the envelope the two already use as contacts.
//
// It checks what the core can know: the contact exists and has accepted, and
// the statement is well formed. Whether the AI agent may message that contact
// is the AI agent's grant and the owner's rule for that contact, which whoever
// keeps the AI agents this Identity Agent holds applies before it calls this
// (ADR-085, decision 7). An error is returned when nothing was sent. A contact
// that takes the message and then refuses it is not heard of (ADR-085,
// decision 8).
func (s *CoreServer) SendAgentPeerMessage(to string, st agentpeer.Statement, words string) error {
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return errors.New("this Identity Agent has no identity yet")
	}
	contact, err := s.DataStore.GetContact(to)
	if err != nil || contact == nil {
		return fmt.Errorf("you and %s are not contacts yet", to)
	}
	if contact.Status != "accepted" {
		return fmt.Errorf("%s has not accepted your introduction yet", to)
	}
	keys, err := s.keySetFor(identity.AID)
	if err != nil {
		return fmt.Errorf("this Identity Agent's messaging keys are unavailable: %w", err)
	}
	st.ToAID = to
	msg, err := agentpeer.Seal(keys, st, words, time.Now())
	if err != nil {
		return err
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, status, err := s.SendDIDCommMessage(identity.AID, to, didcomm.TypeAgentPeerMessage, body)
	if err != nil {
		return fmt.Errorf("%s is not answering: %w", to, err)
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("%s did not take the message (%d)", to, status)
	}
	return nil
}
