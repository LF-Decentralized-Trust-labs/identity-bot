package server

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
)

// One private relay address per relationship (ADR-048 §6).
//
// A pairwise identifier exists so that two counterparties cannot tell they are
// dealing with the same person (ADR-036). An address handed to both of them
// would tell them: the same path at the same relay. So each relationship's
// OOBI names an address made for that relationship alone, a fresh random label
// that is not derived from anything (relayproto.NewAllocationToken).
//
// WHAT THIS DOES NOT HIDE. The relay operator sees every one of these arrive
// down the one session this Identity Agent holds, so it can link all of them to
// each other, and says so (ADR-048 §11). This hides the relationships from one
// another, not from the operator. Spreading relationships across operators, or
// a session per relationship, is what hides them from the operator; neither is
// built here.
//
// WHAT IT COSTS. One allocate request and one bind (on every later session)
// per relationship, and one release when it ends. The relay keeps a label and
// a commitment for each, and the Identity Agent keeps each one's secret in its
// relay record. Nothing else: no extra session, no extra key.

// notRelationshipPools are the pairwise pools whose identifiers are not given to
// a counterparty, so they get no address of their own. A relay enrolment
// identifier is how the relay knows this Identity Agent at all, and it is
// minted before the relay that would give it an address exists.
var notRelationshipPools = map[string]bool{
	privateRelay.pool: true,
	publicRelay.pool:  true,
}

// relayAddressTimeout bounds asking the relay for an address while a
// relationship is being made.
const relayAddressTimeout = 10 * time.Second

// addressForNewRelationship is the address a new pairwise identifier's OOBI is
// written at: an address made for it alone when this Identity Agent uses a
// private relay, otherwise the address it publishes.
//
// When the relay cannot be asked right now (the session is down), the
// relationship is made at the shared address rather than refused, and the log
// says so. That relationship is then in the same position as one made before
// this change: it keeps the shared address (see ADR-048, what is built).
func (s *CoreServer) addressForNewRelationship(pool, aid string) string {
	shared := s.EndpointService.CurrentURL()
	if notRelationshipPools[pool] {
		return shared
	}
	rm := s.currentRelay()
	if rm == nil || rm.Config().Mode != relayproto.ModePrivate {
		return shared
	}
	ctx, cancel := context.WithTimeout(s.backgroundContext(), relayAddressTimeout)
	defer cancel()
	a, err := rm.AllocateFor(ctx, aid)
	if err != nil {
		log.Printf("[relay] %s is given the shared address, which links it to every other "+
			"relationship made that way, because the relay would not make one for it: %v", aid, err)
		return shared
	}
	return strings.TrimRight(a.URL, "/")
}

// endRelationshipAddress gives back the address made for a relationship that
// has ended. It answers nothing from this moment; if the relay cannot be asked
// now it is given back on a later session.
func (s *CoreServer) endRelationshipAddress(relationshipAID string) {
	if relationshipAID == "" {
		return
	}
	rm := s.currentRelay()
	if rm == nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.backgroundContext(), relayAddressTimeout)
	defer cancel()
	if err := rm.ReleaseFor(ctx, relationshipAID); err != nil {
		log.Printf("[relay] the address of the ended relationship %s is not given back yet "+
			"(it already answers nothing, and is given back on a later session): %v", relationshipAID, err)
	}
}
