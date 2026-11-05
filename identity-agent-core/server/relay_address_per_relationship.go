package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
	"identity-agent-core/relay"
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
//
// A RELATIONSHIP IS NEVER MADE AT THE SHARED ADDRESS INSTEAD. If the relay will
// not make an address for it, the relationship is refused with an error that
// says to try again (errRelayAddressUnavailable): a relationship quietly given
// the shared address is linked to every other one given it, which is the thing
// this exists to prevent, and nothing afterwards says so.

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

// errRelayAddressUnavailable is a relationship refused for want of an address
// of its own. It is worth trying again; nothing was made that has to be undone.
var errRelayAddressUnavailable = errors.New("the relay would not make an address for this relationship just now; try again")

type relayAddressRefusal struct{ cause error }

func (e *relayAddressRefusal) Error() string {
	return errRelayAddressUnavailable.Error() + ": " + e.cause.Error()
}
func (e *relayAddressRefusal) Unwrap() []error {
	return []error{errRelayAddressUnavailable, e.cause}
}

// writeRelationshipError answers a failure to make a relationship: a retryable
// refusal is a 503 with a Retry-After, the limit is a 429, and anything else is
// the caller's own status.
func writeRelationshipError(w http.ResponseWriter, fallback int, what string, err error) {
	switch {
	case errors.Is(err, errRelayAddressUnavailable):
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, what, err.Error())
	case errors.Is(err, relay.ErrTooManyAddresses):
		writeError(w, http.StatusTooManyRequests, what, err.Error())
	default:
		writeError(w, fallback, what, err.Error())
	}
}

// sharedAddress is the address this Identity Agent publishes for itself.
func (s *CoreServer) sharedAddress() string {
	if base, ok := s.heldRelayBase(); ok {
		return base
	}
	if s.EndpointService != nil {
		return s.EndpointService.CurrentURL()
	}
	return ""
}

// usesPerRelationshipAddresses is whether new relationships in pool each get an
// address of their own.
func (s *CoreServer) usesPerRelationshipAddresses(pool string) (*relay.Manager, bool) {
	if notRelationshipPools[pool] {
		return nil, false
	}
	rm := s.currentRelay()
	if rm == nil || rm.Config().Mode != relayproto.ModePrivate {
		return nil, false
	}
	return rm, true
}

// addressForNewRelationship is the address a new pairwise identifier's OOBI is
// written at: an address made for it alone when this Identity Agent uses a
// private relay, otherwise the address it publishes.
func (s *CoreServer) addressForNewRelationship(pool, aid string) (string, error) {
	rm, own := s.usesPerRelationshipAddresses(pool)
	if !own {
		return s.sharedAddress(), nil
	}
	ctx, cancel := context.WithTimeout(s.backgroundContext(), relayAddressTimeout)
	defer cancel()
	a, err := rm.AllocateFor(ctx, aid)
	if err != nil {
		if errors.Is(err, relay.ErrTooManyAddresses) {
			return "", err
		}
		log.Printf("[relay] no relationship was made for %s, because the relay would not make an address for it: %v", aid, err)
		return "", &relayAddressRefusal{cause: err}
	}
	return strings.TrimRight(a.URL, "/"), nil
}

// addressBaseFor is where the relationship aid is reached: the address made for
// it, else the relay address the request came to or this Identity Agent holds.
// Everything written for a counterparty names this, never the shared address
// when the relationship has one of its own.
func (s *CoreServer) addressBaseFor(r *http.Request, aid string) (string, bool) {
	if rm := s.currentRelay(); rm != nil {
		if a := rm.AddressFor(aid); a != nil && a.URL != "" {
			return strings.TrimRight(a.URL, "/"), true
		}
	}
	if r != nil {
		return s.relayAddressBase(r)
	}
	return s.heldRelayBase()
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

// What ends which relationship. An invitation, a ceremony and a machine are
// each ended by something other than a contact being deleted, and none of them
// knows the pairwise identifier made for it unless it was written down.
// relationshipEnds is that record: a handle for the thing that can end, and the
// identifiers made for it. Ending a handle gives their addresses back.
type relationshipEnds struct {
	mu      sync.Mutex
	path    string
	Handles map[string][]string `json:"handles"`
}

const relationshipEndsFileName = "relationship-ends.json"

func (s *CoreServer) endsOrLoad() *relationshipEnds {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.relationshipEndsHeld == nil {
		s.relationshipEndsHeld = loadRelationshipEnds(s.DataDir)
	}
	return s.relationshipEndsHeld
}

// madeFor records that the relationship aid was made for handle.
func (s *CoreServer) madeFor(handle, aid string) {
	if handle == "" || aid == "" {
		return
	}
	e := s.endsOrLoad()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Handles[handle] = append(e.Handles[handle], aid)
	if err := e.saveLocked(); err != nil {
		log.Printf("[relay] could not record that %s was made for %s, so ending it will not give its address back: %v", aid, handle, err)
	}
}

// endHandle ends every relationship made for handle.
func (s *CoreServer) endHandle(handle string) {
	e := s.endsOrLoad()
	e.mu.Lock()
	aids := e.Handles[handle]
	delete(e.Handles, handle)
	_ = e.saveLocked()
	e.mu.Unlock()
	for _, aid := range aids {
		s.endRelationshipAddress(aid)
	}
}

// published remembers the address each relationship's endpoint record last said,
// so a change is published once and a loss is published as a withdrawal.
type relationshipPublishedSet struct {
	sync.Mutex
	m map[string]string
}

// republishRelationshipAddresses tells each relationship's witnesses where that
// relationship is reached now: its own address, which moves when the relay's
// URL does and is gone when the relay no longer holds it (an empty location is
// a withdrawal, so nobody keeps arriving at a dead address). Only what changed
// is published.
// publishLocation is how a relationship's address is published: to its witnesses,
// unless something else was set.
func (s *CoreServer) publishLocation() func(ctx context.Context, aid, address string) error {
	if s.publishEndpoint != nil {
		return s.publishEndpoint
	}
	return s.PublishEndpointLocation
}

func (s *CoreServer) publishedFor() *relationshipPublishedSet {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.relationshipPublishedHeld == nil {
		s.relationshipPublishedHeld = &relationshipPublishedSet{m: map[string]string{}}
	}
	return s.relationshipPublishedHeld
}

func (s *CoreServer) republishRelationshipAddresses(rm *relay.Manager) {
	now := map[string]string{}
	if rm.GetStatus().Active {
		for _, a := range rm.RelationshipAddresses() {
			now[a.RAID] = strings.TrimRight(a.URL, "/")
		}
	}
	pub := s.publishedFor()
	pub.Lock()
	var todo []struct{ aid, url string }
	for aid, url := range now {
		if pub.m[aid] != url {
			todo = append(todo, struct{ aid, url string }{aid, url})
		}
	}
	for aid := range pub.m {
		if _, held := now[aid]; !held {
			todo = append(todo, struct{ aid, url string }{aid, ""})
		}
	}
	for _, t := range todo {
		if t.url == "" {
			delete(pub.m, t.aid)
		} else {
			pub.m[t.aid] = t.url
		}
	}
	pub.Unlock()
	for _, t := range todo {
		t := t
		s.inBackground(func(ctx context.Context) {
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if err := s.publishLocation()(ctx, t.aid, t.url); err != nil {
				log.Printf("[relay] could not publish where %s is reached: %v", t.aid, err)
				// So the next change tries again.
				pub.Lock()
				delete(pub.m, t.aid)
				pub.Unlock()
			}
		})
	}
}
