package server

import (
	"fmt"
	"strings"
)

// The first message from somebody you already know.
//
// Inbound delivery refuses a sender that is not in the peers file, and that is
// right: registering a peer is an owner action, and the alternative — resolving
// anything an anonymous caller names — is how a POST becomes a way to make this
// agent do unbounded work.
//
// But it left first contact impossible. The sender can learn the recipient's
// keys, because a DID document is public. The recipient cannot learn the
// sender's, so the first envelope between two agents that have never exchanged
// a message is always refused. That was found on hardware: an organisation
// could read a customer's keys and its message still came back 403, and
// registering the peer by hand made the identical message land.
//
// The way through is to notice that "unknown" and "stranger" are different
// things. An ACCEPTED CONTACT is somebody the owner has already looked at and
// approved — the relationship exists, the address is recorded, and only the
// messaging keyset was never fetched. Resolving that is not trusting an
// anonymous caller; it is finishing a setup step the owner already authorised.
//
// A sender who is not an accepted contact is still refused, and nothing is
// resolved on their say-so.

// resolveKnownContactAsPeer registers a peer for a sender the owner has already
// accepted, so a first message from them is not refused.
//
// Returns false when the sender is not an accepted contact — the ordinary case
// for a stranger, and not an error.
func (s *CoreServer) resolveKnownContactAsPeer(aid string) (bool, error) {
	if s.DataStore == nil {
		return false, nil
	}
	contact, err := s.DataStore.GetContact(aid)
	if err != nil || contact == nil {
		return false, nil
	}
	// Accepted, specifically. A pending or rejected contact is one the owner has
	// not agreed to hear from, and treating "we have a row for them" as consent
	// would make an unanswered introduction into an open door.
	if contact.Status != "accepted" {
		return false, nil
	}
	if contact.OobiURL == "" {
		return false, fmt.Errorf("%s is an accepted contact but has no recorded address", aid)
	}

	base, err := agentBaseFromOOBI(contact.OobiURL)
	if err != nil {
		return false, err
	}
	// The same fetch-and-register the outbound path uses, against an address
	// that came from the contact record rather than from the caller. A sender
	// cannot point this at anything of its choosing.
	if err := s.rememberPeerAt(aid, base); err != nil {
		return false, err
	}
	return true, nil
}

// agentBaseFromOOBI recovers the agent's base URL from an OOBI.
//
// An OOBI is the agent's address with a well-known path on the end, so the base
// is what precedes that path. Parsed rather than assumed: an OOBI that does not
// have the expected shape is refused rather than turned into a guess at a
// hostname, because a guess here is a request sent somewhere nobody chose.
func agentBaseFromOOBI(oobi string) (string, error) {
	oobi = strings.TrimSpace(oobi)
	if !strings.HasPrefix(oobi, "http://") && !strings.HasPrefix(oobi, "https://") {
		return "", fmt.Errorf("an OOBI must be an http(s) URL")
	}
	// Drop any query — role=controller and friends belong to the OOBI, not to
	// the agent's address.
	if i := strings.Index(oobi, "?"); i >= 0 {
		oobi = oobi[:i]
	}

	for _, marker := range []string{"/public/oobi/", "/oobi/"} {
		if i := strings.Index(oobi, marker); i > 0 {
			return strings.TrimRight(oobi[:i], "/"), nil
		}
	}
	// The did:webs layout puts the identifier first: {base}/{aid}/oobi.
	if strings.HasSuffix(oobi, "/oobi") {
		trimmed := strings.TrimSuffix(oobi, "/oobi")
		if i := strings.LastIndex(trimmed, "/"); i > 0 {
			return strings.TrimRight(trimmed[:i], "/"), nil
		}
	}
	return "", fmt.Errorf("%q is not a recognisable OOBI, so there is no address in it", oobi)
}
