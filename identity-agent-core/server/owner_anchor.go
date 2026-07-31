package server

import (
	"fmt"
)

// Reading who owns an organisation out of its own key event log.
//
// An organisation names its owner in the event that creates it. That placement
// is the point: a self-addressing identifier is the digest of its inception
// event, so the owner is part of what the identity IS. It cannot be added,
// removed or altered afterwards without producing a different organisation.
//
// The alternative — a record beside the database — was what this replaces, and
// it failed in three ways at once. It could be rewritten by anyone who could
// write the file, silently. It could not be read by anyone not on that machine,
// so nobody could verify who owned an organisation running on somebody else's
// hardware. And it left a window, between creating the identity and writing the
// record, in which an organisation answered to itself.
//
// None of those are guarded against here. They stop being reachable, because
// there is no earlier moment for an organisation to be unowned in.

// ownerRole is the seal role naming who an identity answers to.
const ownerRole = "owner"

// ownerFromKEL returns the owner named in an identity's inception event.
//
// Only the inception is consulted, deliberately. A later event cannot introduce
// an owner where there was none: an organisation that was not owned when it was
// created never had a founder, and letting a subsequent event claim otherwise
// would reintroduce exactly the silent-overwrite problem the anchor exists to
// remove. Changing owners is a rotation, and rotation is a separate ceremony
// with its own rules.
//
// Returns "" when the identity names no owner, which is the ordinary case for a
// person's own agent: its identity is delegated, so its delegator is already in
// the event and it needs no separate anchor.
func ownerFromKEL(kel []map[string]interface{}) (string, error) {
	if len(kel) == 0 {
		return "", fmt.Errorf("no key events to read an owner from")
	}

	inception := kel[0]
	if t, _ := inception["t"].(string); t != "icp" && t != "dip" {
		return "", fmt.Errorf("the first event is %q, not an inception", t)
	}

	seals, ok := inception["a"].([]interface{})
	if !ok {
		return "", nil
	}
	for _, raw := range seals {
		seal, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if role, _ := seal["r"].(string); role != ownerRole {
			continue
		}
		aid, _ := seal["i"].(string)
		if aid == "" {
			// A seal claiming the owner role and naming nobody is malformed.
			// Reported rather than skipped: silently ignoring it would let a
			// broken organisation look like an unowned one, and those need
			// different answers.
			return "", fmt.Errorf("the inception event has an owner seal naming no identity")
		}
		return aid, nil
	}
	return "", nil
}

// ownerAnchorSeal builds the seal that names an owner, so the shape is written
// in one place and read in one place.
func ownerAnchorSeal(ownerAID string) map[string]interface{} {
	return map[string]interface{}{"i": ownerAID, "r": ownerRole}
}

// ownerFromOwnIdentity reads the owner this agent's own identity names.
func (s *CoreServer) ownerFromOwnIdentity(aid string) (string, error) {
	if s.KeriDriver == nil {
		return "", fmt.Errorf("no KERI driver to read the log with")
	}
	kel, err := s.KeriDriver.GetKel(aid)
	if err != nil {
		return "", err
	}
	return ownerFromKEL(kel.KEL)
}

// publicKeyOf resolves the current signing key of an identity this agent knows
// about — the owner is a counterparty, so it is on the contact side.
func (s *CoreServer) publicKeyOf(aid string) (string, error) {
	if s.DataStore == nil {
		return "", fmt.Errorf("no store to resolve %s from", aid)
	}
	if record, err := s.DataStore.GetContactKEL(aid); err == nil && record != nil {
		if record.CurrentPublicKey != "" {
			return record.CurrentPublicKey, nil
		}
	}
	contacts, err := s.DataStore.GetContacts()
	if err != nil {
		return "", err
	}
	for _, c := range contacts {
		if c.AID == aid && c.PublicKey != "" {
			return c.PublicKey, nil
		}
	}
	return "", fmt.Errorf("no key on file for %s", aid)
}
