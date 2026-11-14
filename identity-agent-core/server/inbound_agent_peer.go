package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"identity-agent-core/agentpeer"
	"identity-agent-core/didcomm"
)

// A message from an AI agent another Identity Agent holds (ADR-080), arriving
// inside the envelope between the two Identity Agents as contacts.
//
// What this does and does not decide. The envelope has said which Identity
// Agent sent it. Here the core checks that sender is an accepted contact and
// that the statement it signed is well formed, for this Identity Agent, from
// the Identity Agent the envelope names, and covers the words
// (agentpeer.Verify), and then hands the message to whoever keeps the AI agents
// this Identity Agent holds and their conversations. That keeper is an add-on's
// (ADR-068), and so are the rules it applies: which of its AI agents the sender
// may reach, how often, and how many of its asks may be unanswered at once. With no keeper registered every such message is refused, so an
// Identity Agent that holds no AI agents takes nothing from another Identity
// Agent's.

// PeerMessageKeeper takes a message that passed the core's checks, and applies
// the owner's own rule for the sending contact before keeping it. It
// returns an error to refuse it; the sender is told nothing of why (see
// dispatchInbound).
type PeerMessageKeeper func(from string, s agentpeer.Statement, m agentpeer.Message) error

// OnAgentPeerMessage registers who keeps AI agents' conversations (add-on layer, at startup).
func (s *CoreServer) OnAgentPeerMessage(k PeerMessageKeeper) { s.peerMessageKeeper = k }

func init() { registerInboundAction(agentPeerMessage{}) }

type agentPeerMessage struct{}

func (agentPeerMessage) Type() string { return didcomm.TypeAgentPeerMessage }

func (agentPeerMessage) Perform(s *CoreServer, in InboundMessage) error {
	if s.peerMessageKeeper == nil {
		return errors.New("this Identity Agent keeps no AI agents' conversations, so it takes no message for one")
	}
	if err := s.isAcceptedContact(in.FromAID); err != nil {
		return err
	}
	peer, ok, err := s.peerFor(in.FromAID)
	if err != nil || !ok {
		return fmt.Errorf("the keys of %s are not known", in.FromAID)
	}
	var m agentpeer.Message
	if err := json.Unmarshal(in.Body, &m); err != nil {
		return fmt.Errorf("the message could not be read: %w", err)
	}
	st, err := agentpeer.Verify(m, &peer.DID, in.FromAID, in.ToAID, time.Now())
	if err != nil {
		return err
	}
	if err := s.peerMessageKeeper(in.FromAID, st, m); err != nil {
		return err
	}
	log.Printf("[agentpeer] %s from %s for %s taken", st.Kind, in.FromAID, st.ToAgent)
	return nil
}

// isAcceptedContact refuses an Identity Agent that is not a contact this one has
// accepted: a message or a directory between AI agents travels only between
// contacts (ADR-080).
func (s *CoreServer) isAcceptedContact(aid string) error {
	contact, err := s.DataStore.GetContact(aid)
	if err != nil || contact == nil {
		return fmt.Errorf("%s is not a contact", aid)
	}
	if contact.Status != "accepted" {
		return fmt.Errorf("%s is a contact that is %s, not accepted", aid, contact.Status)
	}
	return nil
}
