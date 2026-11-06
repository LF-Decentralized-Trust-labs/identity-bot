package server

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/endpointrecord"
	"identity-agent-core/secureenclave"
	"identity-agent-core/store"
)

// Keeping a published address true.
//
// Publishing where an identity is only helps while the published answer is
// still the right one. A relay that has moved, or died, leaves a signed record
// pointing somewhere nothing is listening — which is worse than never having
// published, because a counterparty now has a confident wrong answer instead of
// an obviously stale one.
//
// So the address is republished when it changes, from the place that knows it
// changed. relay.Manager reports both edges — gained and lost — and this is
// what it reports them to.
//
// Whose key signs matters here. Private keys never leave the controller device,
// so this core cannot sign for the root identity: those records are signed by
// the client and published through the handler below. It CAN sign for pairwise
// AIDs, whose keys it derives from the root seed it was handed at onboarding,
// and those are the AIDs that carry relationships — which is exactly where a
// dead address does its damage.

// signingSeedForAID re-derives the Ed25519 seed for one of this agent's own
// pairwise AIDs.
//
// Refuses the root deliberately rather than falling back to something that
// would work. The root identity's key is the controller's, and a core that
// quietly signed on its behalf would be claiming an authority it is not
// supposed to have — even for something as small as an address.
func (s *CoreServer) signingSeedForAID(aid string) ([]byte, error) {
	if aid == "" {
		return nil, fmt.Errorf("no AID given")
	}
	if id, _ := s.DataStore.GetIdentity(); id != nil && id.AID == aid {
		return nil, fmt.Errorf("the root identity signs its own endpoint records on the controller device")
	}

	contacts, err := s.DataStore.GetContacts()
	if err != nil {
		return nil, fmt.Errorf("read contacts: %w", err)
	}
	var match *store.ContactRecord
	for i := range contacts {
		if contacts[i].RelationshipAID == aid {
			match = &contacts[i]
			break
		}
	}
	if match == nil {
		return nil, fmt.Errorf("%s is not one of this agent's pairwise identities", aid)
	}

	root, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		return nil, fmt.Errorf("root seed unavailable: %w", err)
	}
	return backup.DerivePairwiseSeed(root, match.RelationshipIndex, 0)
}

// lastIssued is when the last record for each identifier was issued from here,
// so two changes inside one second still make two records, the second later.
var (
	lastIssuedMu sync.Mutex
	lastIssued   = map[string]time.Time{}
)

func issueTimeFor(aid string) time.Time {
	lastIssuedMu.Lock()
	defer lastIssuedMu.Unlock()
	now := time.Now().UTC().Truncate(time.Second)
	if last, ok := lastIssued[aid]; ok && !now.After(last) {
		now = last.Add(time.Second)
	}
	lastIssued[aid] = now
	return now
}

// PublishEndpointLocation signs an endpoint record (endpointrecord) for one of
// this agent's pairwise AIDs and sends it to that AID's witnesses.
//
// address is where the identity can be reached; only its origin is signed. An
// empty address is meaningful and is passed through: it signs a withdrawal,
// which is how an identity says "not here any more" rather than leaving a dead
// address published behind it.
func (s *CoreServer) PublishEndpointLocation(ctx context.Context, aid, address string) error {
	if s.WitnessService == nil {
		return fmt.Errorf("witness service unavailable — nowhere to publish")
	}
	origin := ""
	if address != "" {
		var err error
		if origin, err = endpointrecord.OriginOf(address); err != nil {
			return err
		}
	}

	seed, err := s.signingSeedForAID(aid)
	if err != nil {
		return err
	}
	record, err := endpointrecord.Sign(aid, origin, issueTimeFor(aid), seed)
	if err != nil {
		return err
	}
	// The signature is inside the record, over the rest of it, so what a
	// witness stores and serves is exactly what was signed.
	return s.WitnessService.PublishEndpointRecord(ctx, aid, map[string]interface{}{
		"type": record.Type, "aid": record.AID, "origin": record.Origin,
		"issued": record.Issued, "signature": record.Signature,
	})
}

// onRelayEndpointChanged republishes an address when the relay reports it
// gained or lost one.
//
// Loss publishes an empty location on purpose. Saying nothing would leave the
// last address standing as the current answer, and a counterparty would keep
// arriving somewhere nothing is listening; saying "not here" at least lets them
// stop and look elsewhere.
func (s *CoreServer) onRelayEndpointChanged(aid string) func(url string, active bool) {
	return func(url string, active bool) {
		ctx := s.AppCtx
		if ctx == nil {
			ctx = context.Background()
		}
		published := url
		if !active {
			published = ""
		}
		if err := s.PublishEndpointLocation(ctx, aid, published); err != nil {
			// Not fatal. The agent is still reachable at whatever it just
			// acquired; what has failed is telling people about it, and the
			// next change will try again.
			log.Printf("[endpoint] could not publish address for %s: %v", aid, err)
			return
		}
		if active {
			log.Printf("[endpoint] published %s for %s", url, aid)
		} else {
			log.Printf("[endpoint] published loss of address for %s", aid)
		}
	}
}
