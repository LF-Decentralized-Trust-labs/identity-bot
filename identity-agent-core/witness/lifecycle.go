package witness

import (
	"context"
	"log"
)

// Turning a new contact into a witness, when they can be one.
//
// The design is that people witness for the people they already know. That only
// happens if something acts on it: adding a contact is the moment the pool can
// grow, and until now nothing looked. Witness requests went out only when an
// existing witness dropped offline, so a fresh identity accumulated contacts
// and stayed on its bootstrap witnesses indefinitely.
//
// Both sides have to agree, and both sides apply the same test. Being asked is
// not being enrolled: the contact evaluates the request against its own
// capability and refuses if it cannot serve.

// ConsiderContactAsWitness asks a newly accepted contact to witness, if it can.
//
// Safe to call whenever a contact is accepted or updated. Every reason not to
// proceed is a quiet return rather than an error: this runs as a side effect of
// somebody adding a contact, and failing to enrol a witness must never fail
// that.
func (s *Service) ConsiderContactAsWitness(ctx context.Context, contactAID string) {
	if s == nil || contactAID == "" || s.Contacts == nil {
		return
	}
	c, _ := s.Contacts.GetContact(contactAID)
	if c == nil || c.IsWitness {
		return
	}
	if !IsContactWitnessEligible(*c) {
		return
	}
	// Enough witnesses already. Asking anyway would enrol more observers than
	// the threshold needs, and every one of them learns something about who
	// this identity is connected to.
	if s.ActiveWitnessCount() >= TargetContactWitnesses {
		return
	}

	// Can this contact actually witness? A contact reachable only on a phone
	// cannot: witnessing means answering when somebody else publishes an event,
	// and a phone is not there for it. A phone paired with a computer can,
	// because the computer answers — which is why this asks what backend the
	// contact runs rather than what device the person holds.
	meta, _ := s.Store.GetContactMeta(contactAID)
	if meta == nil || meta.BackendType == "" {
		// Nothing published, so nothing to judge. Left alone rather than
		// assumed either way: asking a contact that cannot serve wastes a
		// request, and assuming it cannot would exclude everyone whose backend
		// this agent has simply not learned yet. It is reconsidered whenever
		// the contact is resolved again.
		return
	}
	if !IsBackendEligible(meta.BackendType) {
		return
	}
	// Peers witness only for their own kind. An organization writing itself
	// into an individual's founding event publishes a connection that person
	// never chose and cannot remove, because an inception cannot be amended.
	if !s.peerWitnessAllowed(meta) {
		return
	}

	if err := s.SendWitnessRequest(ctx, contactAID); err != nil {
		log.Printf("[witness] could not ask %s to witness: %v", contactAID, err)
		return
	}
	if s.OnEvent != nil {
		s.OnEvent("witness_requested", map[string]interface{}{"contact_aid": contactAID})
	}
}

// RecordContactCapability stores what a contact published about itself.
//
// Called when a contact's OOBI is resolved. Each field decides something later
// and none can be worked out afterwards: the backend type decides whether the
// contact can be asked to witness at all, the witness key is what an event
// would have to name to designate it, and the entity type decides whether the
// two of us may witness for each other.
func (s *Service) RecordContactCapability(contactAID, backendType, witnessKey, entityType string) {
	if s == nil || contactAID == "" || s.Store == nil {
		return
	}
	if backendType == "" && witnessKey == "" && entityType == "" {
		return
	}
	meta, _ := s.Store.GetContactMeta(contactAID)
	if meta == nil {
		meta = &ContactMeta{ContactAID: contactAID}
	}
	if backendType != "" {
		meta.BackendType = backendType
	}
	if witnessKey != "" {
		meta.WitnessKey = witnessKey
	}
	// Which kind of entity this contact is decides whether it may witness for
	// us at all, and it cannot be worked out later from anything else.
	if entityType != "" {
		meta.EntityType = entityType
	}
	_ = s.Store.SaveContactMeta(*meta)
}

// WitnessesForNewIdentity returns the witnesses to designate in an inception
// event, and how many of them must receipt for it to count as witnessed.
//
// Called at the one moment designation is possible without a rotation. What
// comes back is witness KEYS: an event names the key its receipts verify
// against, so a witness this agent knows only as a contact cannot be named
// until that contact publishes one.
//
// An empty result is a real answer. An identity with no designated witnesses is
// correctly reported as unwitnessed, and that is a smaller problem than one
// that names observers whose receipts nobody can check — in an event that can
// never be amended.
func (s *Service) WitnessesForNewIdentity(kind AidKind, aid string) (keys []string, toad int) {
	if s == nil {
		return nil, 0
	}
	candidates, err := s.enrolledWitnesses(kind, aid)
	if err != nil {
		return nil, 0
	}
	return DesignatableWitnesses(candidates)
}

// peerWitnessAllowed reports whether a contact may act as a peer witness for
// this agent, on the entity-kind boundary alone.
//
// Commercial witnesses do not come through here: they are not peers, and
// excluding them would leave a new individual identity with nobody at all.
func (s *Service) peerWitnessAllowed(meta *ContactMeta) bool {
	if s.OurEntityType == nil {
		// This agent does not know what it is, so it cannot know whether a
		// contact is the same kind. Refused rather than assumed: allowing it
		// wrongly publishes somebody's root identifier permanently, and
		// refusing it wrongly costs one witness until the profile is set.
		return false
	}
	if meta == nil {
		return false
	}
	return PeerWitnessAllowedAcross(s.OurEntityType(), NormaliseEntityType(meta.EntityType))
}
