package server

import (
	"encoding/json"
	"fmt"
	"log"

	"identity-agent-core/didcomm"
)

// Introducing yourself, inside the envelope.
//
// This used to be a separate plaintext endpoint: an introduction was POSTed as
// JSON to a peer's /api/exchange, carrying a claim about who sent it and a
// signature the receiver had to check for itself. Two things were wrong with
// that shape rather than with its implementation.
//
// It was a second way in. Everything else between agents rides one authenticated
// envelope, and a second door with its own rules is a second door to get right —
// the issuer of a credential was once read from a body on exactly this pattern.
//
// And it could not be signed. Signing as the identity requires the identity's
// key, which on a computer belongs to the owner's device and never reaches the
// agent, so the introduction went out unsigned and the far side refused it. The
// envelope has no such problem: it is authenticated by the messaging keys the
// agent does hold, and the identifier commits to those.
//
// So an introduction is now a message like any other, and the far side learns
// who sent it the same way it learns who sent anything.

// introduceOurselvesTo sends a request to connect to somebody at oobiURL.
//
// Establishes the peer first, from an address the OWNER supplied — adding a
// contact is an owner action, so this is not a fetch on a stranger's say-so.
// The keys that come back are checked against what that identifier commits to
// before anything is sent to them.
func (s *CoreServer) introduceOurselvesTo(aid, oobiURL string, body map[string]interface{}) error {
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return fmt.Errorf("this agent has no identity to introduce")
	}
	if aid == "" || oobiURL == "" {
		return fmt.Errorf("an introduction needs somebody to send it to")
	}

	base, berr := agentBaseFromOOBI(oobiURL)
	if berr != nil {
		return fmt.Errorf("cannot tell where %s is from %q: %w", aid, oobiURL, berr)
	}
	if err := s.rememberPeerAt(aid, base); err != nil {
		return fmt.Errorf("could not establish %s as a peer: %w", aid, err)
	}

	raw, merr := json.Marshal(body)
	if merr != nil {
		return merr
	}
	_, status, serr := s.SendDIDCommMessage(identity.AID, aid, didcomm.TypeContactRequest, raw)
	if serr != nil {
		return serr
	}
	// The status is checked separately from the error, because a recipient that
	// refuses answers 4xx and produces no error at all — a caller reading only
	// the error reports every rejection as a delivery.
	if status < 200 || status >= 300 {
		return fmt.Errorf("%s refused the introduction (%d)", aid, status)
	}
	log.Printf("[introduction] told %s who we are", aid)
	return nil
}

// tellThemWeAccepted lets somebody know their request was agreed to.
//
// Sent as an acknowledgement rather than a second request: they asked, and this
// is the answer. By this point they are already a peer, because agreeing to
// them established one from the key history they proved themselves with.
func (s *CoreServer) tellThemWeAccepted(aid string, body map[string]interface{}) error {
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return fmt.Errorf("this agent has no identity to answer as")
	}
	raw, merr := json.Marshal(body)
	if merr != nil {
		return merr
	}
	_, status, serr := s.SendDIDCommMessage(identity.AID, aid, didcomm.TypeAck, raw)
	if serr != nil {
		return serr
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("%s did not accept the acknowledgement (%d)", aid, status)
	}
	return nil
}
