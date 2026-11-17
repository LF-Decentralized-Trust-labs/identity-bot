package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"identity-agent-core/agentpeer"
	"identity-agent-core/didcomm"
)

// The AI agents a contact says this Identity Agent may reach (ADR-085), as
// that contact sends them. The core checks the sender is an accepted contact and
// that the list can be shown as it stands (agentpeer.Directory.Check), and hands
// it to whoever keeps the AI agents this Identity Agent holds, which keeps it for writing and showing "name@alias". Whether a
// message goes is the sender's grant and rule and the receiver's own rule, never
// this list. With no keeper registered, none is taken.

// PeerDirectoryKeeper keeps a directory that passed the core's checks.
type PeerDirectoryKeeper func(from string, d agentpeer.Directory) error

// OnAgentPeerDirectory registers who keeps contacts' directories (add-on layer, at startup).
func (s *CoreServer) OnAgentPeerDirectory(k PeerDirectoryKeeper) { s.peerDirectoryKeeper = k }

func init() { registerInboundAction(agentPeerDirectory{}) }

type agentPeerDirectory struct{}

func (agentPeerDirectory) Type() string { return didcomm.TypeAgentPeerDirectory }

func (agentPeerDirectory) Perform(s *CoreServer, in InboundMessage) error {
	if s.peerDirectoryKeeper == nil {
		return errors.New("this Identity Agent keeps no AI agents, so it takes no list of another Identity Agent's")
	}
	if err := s.isAcceptedContact(in.FromAID); err != nil {
		return err
	}
	var d agentpeer.Directory
	if err := json.Unmarshal(in.Body, &d); err != nil {
		return fmt.Errorf("the directory could not be read: %w", err)
	}
	if err := d.Check(); err != nil {
		return err
	}
	if err := s.peerDirectoryKeeper(in.FromAID, d); err != nil {
		return err
	}
	log.Printf("[agentpeer] %s lists %d AI agents we may reach", in.FromAID, len(d.Agents))
	return nil
}

// SendAgentPeerDirectory tells an accepted contact which of the AI agents this
// Identity Agent holds it may reach, by name. What it lists is the owner's
// rule, kept by whoever keeps the AI agents; the core checks the list can be
// shown and carries it.
func (s *CoreServer) SendAgentPeerDirectory(to string, d agentpeer.Directory) error {
	if err := d.Check(); err != nil {
		return err
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return errors.New("this Identity Agent has no identity yet")
	}
	if err := s.isAcceptedContact(to); err != nil {
		return err
	}
	body, err := json.Marshal(d)
	if err != nil {
		return err
	}
	_, status, err := s.SendDIDCommMessage(identity.AID, to, didcomm.TypeAgentPeerDirectory, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("%s did not take the list (%d)", to, status)
	}
	return nil
}
