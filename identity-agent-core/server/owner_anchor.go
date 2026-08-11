package server

import (
	"encoding/json"
	"fmt"
	"strings"
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

// How an owner is written into an event, and why it is a plain KERI seal.
//
// It used to be {"i": <owner>, "r": "owner"} — an identifier and a role. That
// shape is not one KERI defines. The specification has a closed set of seals,
// and a strict reader parses this field as one of them: measured against an
// independent implementation (keriox), an inception carrying the old shape
// could not be PARSED at all. Not "failed validation" — the event was
// unreadable, so an owned organisation's entire log was unreadable to anything
// that did not already agree with us about the shape. For a project whose value
// is that anyone can verify ownership without our software, that was fatal.
//
// So an owner is now an event seal: {"i": <owner>, "s": "0", "d": <owner>},
// naming the owner's inception event exactly. The repeated value is not a
// shortcut — every identity here is self-addressing, so its identifier IS the
// digest of its inception event, and the seal resolves.
//
// The role label is gone, and what replaces it is position. An owner seal is an
// event seal in an ESTABLISHMENT event. That distinction does real work and is
// checked rather than assumed:
//
//   - Interactions anchor event seals too — a registry, a credential issuance,
//     a delegation approval. Reading those as owner changes would let issuing a
//     credential silently reassign an organisation. Establishment-only excludes
//     them.
//   - Rotations already anchor something else: break-glass recovery anchors a
//     DIGEST seal, {"d": ...}. A different shape, so it cannot be confused with
//     an owner however it is read.
//
// Anything that later anchors an event seal in an establishment event for some
// other purpose breaks this, and must be given a shape that cannot be mistaken
// for an owner — or this scheme has to change.

// ownerSealSN is the position an owner seal names: the owner's inception.
const ownerSealSN = "0"

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
		aid, isOwner, err := ownerFromSeal(seal)
		if err != nil {
			return "", err
		}
		if isOwner {
			return aid, nil
		}
	}
	return "", nil
}

// ownerAnchorSeal builds the seal that names an owner, so the shape is written
// in one place and read in one place.
//
// Returned as raw JSON rather than a map, because a seal's field order is part
// of it and marshalling a Go map sorts the keys. The same seal is accepted in
// the specified order and refused in sorted order — measured, not assumed.
func ownerAnchorSeal(ownerAID string) (json.RawMessage, error) {
	if ownerAID == "" {
		return nil, fmt.Errorf("an owner seal must name an owner")
	}
	// Every identity this agent creates is self-addressing, so the identifier is
	// the digest of the inception event and the seal below resolves to a real
	// event. An identifier of another kind would produce a seal whose digest
	// refers to nothing, which reads as valid and cannot be resolved by anyone.
	if !strings.HasPrefix(ownerAID, "E") {
		return nil, fmt.Errorf("%q is not a self-addressing identifier, so its inception "+
			"digest is not its identifier and an owner seal naming it would point at no "+
			"event", ownerAID)
	}
	return json.RawMessage(fmt.Sprintf(`{"i":%q,"s":%q,"d":%q}`,
		ownerAID, ownerSealSN, ownerAID)), nil
}

// ownerFromSeal returns the owner an anchored seal names, if it is one.
//
// Three outcomes, not two. A seal can name an owner, be something else
// entirely, or be an owner seal that is broken — and the third must not
// collapse into the second. An identity whose ownership record is corrupt and
// one that was never owned need different answers: the first is a fault to
// report, the second is the ordinary state of a person's own agent.
func ownerFromSeal(seal map[string]interface{}) (owner string, isOwner bool, err error) {
	// An owner seal is a KERI event seal: exactly these three fields, naming the
	// owner's inception. Anything else — a digest seal from break-glass
	// recovery, a seal with extra fields — is not this function's business.
	if len(seal) != 3 {
		return "", false, nil
	}
	iRaw, hasI := seal["i"]
	sRaw, hasS := seal["s"]
	dRaw, hasD := seal["d"]
	if !hasI || !hasS || !hasD {
		return "", false, nil
	}
	aid, _ := iRaw.(string)
	sn, _ := sRaw.(string)
	d, _ := dRaw.(string)

	if aid == "" || d == "" {
		// The shape of an owner seal with nothing in it. Reported rather than
		// skipped: silently ignoring it would let a broken identity look like
		// an unowned one.
		return "", false, fmt.Errorf("an event seal names no identity or no event, so the " +
			"ownership record is malformed rather than absent")
	}
	if sn != ownerSealSN {
		// A seal naming a later event of some identity. Real, and not a
		// statement about ownership.
		return "", false, nil
	}
	// The seal names the owner's inception, whose digest IS its identifier
	// because every identity here is self-addressing. Where the two disagree the
	// seal refers to some other identity's event and is not an ownership claim.
	if d != aid {
		return "", false, nil
	}
	return aid, true, nil
}

// establishment reports whether an event can carry an owner seal.
func establishment(event map[string]interface{}) bool {
	switch t, _ := event["t"].(string); t {
	case "icp", "dip", "rot", "drt":
		return true
	}
	return false
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
