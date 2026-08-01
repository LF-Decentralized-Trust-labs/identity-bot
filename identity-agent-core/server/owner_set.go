package server

import (
	"fmt"
)

// Who owns an organisation NOW, rather than who founded it.
//
// The inception event names one owner and cannot name more: an organisation is
// founded by somebody, singular, and there is no moment at which it exists
// unowned. That much is settled and is what makes the identifier itself carry
// its ownership.
//
// But a company outliving the arrangement it was founded under is the ordinary
// life of a company. Owners are added, they leave, they are bought out. So the
// set changes, and it changes by ROTATION — an event in the same log, appended
// in order, visible to anyone reading it.
//
// The rule that keeps this from reintroducing the problem the anchor solved:
//
//	an organisation founded WITHOUT an owner can never acquire one.
//
// A later event may reorganise a set that exists. It may not conjure one where
// there was none, because that is precisely the silent claim of ownership the
// anchor was built to make impossible. Founded unowned means unowned forever,
// and the remedy is to found it again properly rather than to append a claim.

// ownersFromKEL returns the current owner set, in the order last recorded.
//
// The inception decides WHETHER the identity is owned. Subsequent owner anchors
// decide by WHOM. An identity whose inception names no owner returns an empty
// set no matter what later events say.
func ownersFromKEL(kel []map[string]interface{}) ([]string, error) {
	founder, err := ownerFromKEL(kel)
	if err != nil {
		return nil, err
	}
	if founder == "" {
		// Unowned at inception. Nothing later can change that, and this is also
		// the ordinary answer for a person's own agent, whose identity is
		// delegated and needs no separate anchor.
		return nil, nil
	}

	owners := []string{founder}
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
// to nobody", which are different statements and must not collapse. An
// organisation cannot rotate itself to having no owners — that would be an
// organisation answering to itself, which is the state this whole mechanism
// exists to make unreachable.
func ownerSetFromEvent(event map[string]interface{}) (owners []string, found bool, err error) {
	seals, ok := event["a"].([]interface{})
	if !ok {
		return nil, false, nil
	}

	seen := map[string]bool{}
	for _, raw := range seals {
		seal, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if role, _ := seal["r"].(string); role != ownerRole {
			continue
		}
		found = true
		aid, _ := seal["i"].(string)
		if aid == "" {
			return nil, false, fmt.Errorf("an owner seal names no identity")
		}
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
