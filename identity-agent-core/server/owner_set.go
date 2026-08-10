package server

import (
	"fmt"
)

// Who an identity answers to NOW, rather than who it answered to at inception.
//
// An identity that has an owner names them in the event that creates it — one
// party or several — and there is no moment at which it exists unowned. That is
// what makes the identifier itself carry its ownership.
//
// Several from the start is not an edge case. An identity created for a child
// answers to whoever holds guardianship, which is often two people; anything
// created jointly is the same shape.
//
// But the arrangement an identity was created under is not the arrangement it
// keeps. Parties are added, they leave, they are bought out, or control is
// deliberately spread so that no one person holds it alone. So the set changes,
// and it changes by ROTATION — an event in the same log, appended in order,
// visible to anyone reading it.
//
// Nothing here is specific to any kind of identity. A guardianship passing to
// somebody else and a person spreading control of their own identity across
// several keys are the same operation, and this reads both.
//
// The rule that keeps it from reintroducing the problem the anchor solved:
//
//	an identity founded WITHOUT an owner can never acquire one.
//
// A later event may reorganise a set that exists. It may not conjure one where
// there was none, because that is precisely the silent claim of ownership the
// anchor was built to make impossible. Founded unowned means unowned forever,
// and the remedy is to found it again properly rather than to append a claim.

// ownersFromKEL returns the current owner set, in the order last recorded.
//
// The inception decides WHETHER the identity is owned, and by whom to begin
// with — one party or several. Subsequent owner anchors decide by whom now. An
// identity whose inception names no owner returns an empty set no matter what
// later events say.
func ownersFromKEL(kel []map[string]interface{}) ([]string, error) {
	if len(kel) == 0 {
		return nil, fmt.Errorf("no key events to read an owner from")
	}
	inception := kel[0]
	if t, _ := inception["t"].(string); t != "icp" && t != "dip" {
		return nil, fmt.Errorf("the first event is %q, not an inception", t)
	}

	// EVERY owner named at inception, not just the first.
	//
	// An identity may be created already answering to more than one party. An
	// identity created for a child answers to whoever holds guardianship, and
	// that is frequently two people rather than one; anything created jointly is
	// the same. Reading only the first seal would silently drop the others, and
	// the identity would go on believing it answered to a smaller set than its
	// own inception event says — with nothing to indicate the difference.
	owners, found, err := ownerSetFromEvent(inception)
	if err != nil {
		return nil, err
	}
	if !found {
		// Unowned at inception. Nothing later can change that, and this is also
		// the ordinary answer for an identity that needs no separate anchor
		// because its inception already names a delegator.
		return nil, nil
	}
	// Later events, newest last, so the final owner anchor wins. Read forwards
	// rather than backwards from the end: an event that is not an owner change
	// must not shadow one, and reading in order is how a log is meant to be
	// read.
	for _, event := range kel[1:] {
		set, found, err := ownerSetFromEvent(event)
		if err != nil {
			return nil, err
		}
		if found {
			owners = set
		}
	}
	return owners, nil
}

// ownerSetFromEvent reads an owner anchor out of one event.
//
// found distinguishes "this event changed the owners" from "this event set them
// to nobody", which are different statements and must not collapse. An identity
// cannot rotate itself to having no owners — that would leave it answering only
// to itself, which is the state this whole mechanism exists to make
// unreachable.
func ownerSetFromEvent(event map[string]interface{}) (owners []string, found bool, err error) {
	seals, ok := event["a"].([]interface{})
	if !ok {
		return nil, false, nil
	}

	// Only an establishment event can name owners.
	//
	// An interaction anchors event seals of exactly the same shape — a registry,
	// a credential issuance, a delegation approval. Without this, issuing a
	// credential would read as reassigning the organisation to the credential.
	if !establishment(event) {
		return nil, false, nil
	}

	seen := map[string]bool{}
	for _, raw := range seals {
		seal, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		aid, isOwner, err := ownerFromSeal(seal)
		if err != nil {
			return nil, false, err
		}
		if !isOwner {
			continue
		}
		found = true
		// A set, not a list. The same owner twice would otherwise count twice
		// towards any threshold, which is how one person becomes a quorum.
		if seen[aid] {
			continue
		}
		seen[aid] = true
		owners = append(owners, aid)
	}

	if found && len(owners) == 0 {
		return nil, false, fmt.Errorf("an event claims to change the owners and names none")
	}
	return owners, found, nil
}

// ownersOfOwnIdentity reads the current owner set of this agent's identity.
func (s *CoreServer) ownersOfOwnIdentity(aid string) ([]string, error) {
	if s.KeriDriver == nil {
		return nil, fmt.Errorf("no KERI driver to read the log with")
	}
	kel, err := s.KeriDriver.GetKel(aid)
	if err != nil {
		return nil, err
	}
	return ownersFromKEL(kel.KEL)
}
