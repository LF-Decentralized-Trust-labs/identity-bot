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
	return PeerAllowedAcross(s.OurEntityType(), NormaliseEntityType(meta.EntityType))
}

// ContactMetaFor exposes what this agent recorded about a contact, so other
// parts of the agent can apply the same boundary without a second store.
func (s *Service) ContactMetaFor(aid string) (*ContactMeta, error) {
	if s == nil || s.Store == nil {
		return nil, nil
	}
	return s.Store.GetContactMeta(aid)
}

// noteDesignationDrift records that this agent has stopped using a witness its
// key log still designates.
//
// The two can only be brought back together by a rotation, which changes the
// identity's keys and is therefore not something to do silently on a witness
// going quiet. So the drift is recorded and surfaced, and whoever controls the
// identity decides when to rotate.
//
// Left visible rather than resolved automatically because the alternative is
// worse in both directions: rotating on every flaky witness would churn the key
// log, and doing nothing at all would leave the agent quietly disagreeing with
// its own published record of who watches it.
func (s *Service) noteDesignationDrift(contactAID, witnessKey string) {
	log.Printf("[witness] no longer using %s, but the key log still designates %s. "+
		"The designated set can only be amended by a rotation, so until one happens a "+
		"verifier will expect receipts from it that will not come.", contactAID, witnessKey)
	if s.OnEvent != nil {
		s.OnEvent("witness_designation_drift", map[string]interface{}{
			"contact_aid": contactAID,
			"witness_key": witnessKey,
			"remedy":      "rotate to cut this witness from the designated set",
		})
	}
}

// DesignationDrift reports witnesses this agent's key log designates that it is
// no longer relying on, and the reverse.
//
// The list a rotation would need to reconcile. Returned rather than acted on:
// changing the designated set means rotating the identity's keys, which is the
// controller's decision and not a maintenance task.
func (s *Service) DesignationDrift(designated []string) (staleInLog []string, usedButNotDesignated []string) {
	if s == nil || s.Contacts == nil {
		return nil, nil
	}
	using := map[string]bool{}
	contacts, err := s.Contacts.GetContacts()
	if err != nil {
		return nil, nil
	}
	for _, c := range contacts {
		if !c.IsWitness {
			continue
		}
		if meta, _ := s.Store.GetContactMeta(c.AID); meta != nil && meta.WitnessKey != "" {
			using[meta.WitnessKey] = true
		}
	}
	for _, b := range BootstrapPool() {
		if b.WitnessKey != "" {
			using[b.WitnessKey] = true
		}
	}

	inLog := map[string]bool{}
	for _, w := range designated {
		inLog[w] = true
		if !using[w] {
			staleInLog = append(staleInLog, w)
		}
	}
	for w := range using {
		if !inLog[w] {
			usedButNotDesignated = append(usedButNotDesignated, w)
		}
	}
	return staleInLog, usedButNotDesignated
}

// resumeWitness starts relying again on a witness that has come back.
//
// Only where the identity never stopped designating it. A witness that was cut
// by a rotation is gone for good and has to be enrolled afresh — the log says
// so, and the log is what verifiers read.
func (s *Service) resumeWitness(contactAID string) {
	c, _ := s.Contacts.GetContact(contactAID)
	if c == nil || c.IsWitness {
		return
	}
	c.IsWitness = true
	if err := s.Contacts.SaveContact(*c); err != nil {
		log.Printf("[witness] %s is answering again but could not be resumed: %v", contactAID, err)
		return
	}
	log.Printf("[witness] %s is answering again and is being relied on once more; the key log "+
		"designated it throughout", contactAID)
	if s.OnEvent != nil {
		s.OnEvent("witness_resumed", map[string]interface{}{"contact_aid": contactAID})
	}
}
