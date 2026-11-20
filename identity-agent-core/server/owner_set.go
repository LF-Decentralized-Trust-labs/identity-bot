package server

import (
	"fmt"

	"identity-agent-core/drivers"
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
// later events say. The reading is drivers.OwnersFromKEL, which the two-log
// ownership check applies too.
func ownersFromKEL(kel []map[string]interface{}) ([]string, error) {
	return drivers.OwnersFromKEL(kel)
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
