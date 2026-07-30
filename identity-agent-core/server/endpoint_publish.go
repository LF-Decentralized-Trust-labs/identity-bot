package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"

	"identity-agent-core/backup"
	"identity-agent-core/drivers"
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

// PublishEndpointLocation signs a location record for one of this agent's
// pairwise AIDs and sends it to that AID's witnesses.
//
// An empty url is meaningful and is passed through: it nullifies the location,
// which is how an identity says "not here any more" rather than leaving a dead
// address published behind it.
func (s *CoreServer) PublishEndpointLocation(ctx context.Context, aid, url string) error {
	if s.KeriDriver == nil {
		return fmt.Errorf("KERI driver unavailable")
	}
	if s.WitnessService == nil {
		return fmt.Errorf("witness service unavailable — nowhere to publish")
	}

	seed, err := s.signingSeedForAID(aid)
	if err != nil {
		return err
	}

	built, err := s.KeriDriver.EndpointLocation(&drivers.DriverEndpointLocationRequest{
		EID: aid, URL: url, Scheme: "https",
	})
	if err != nil {
		return err
	}

	raw, err := base64.StdEncoding.DecodeString(built.RawBytesB64)
	if err != nil {
		return fmt.Errorf("endpoint record was not decodable: %w", err)
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), raw)

	record := built.RpyEvent
	if record == nil {
		return fmt.Errorf("driver returned no record body")
	}
	// The signature travels beside the record rather than inside it: the SAID
	// is computed over the body, so folding a signature in would change the
	// thing being identified.
	record["signature"] = secureenclave.EncodeSignature(sig)

	return s.WitnessService.PublishEndpointRecord(ctx, aid, record)
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
