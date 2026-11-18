package server

import (
	"identity-agent-core/store"
	"identity-agent-core/witness"
)

// contactView is a contact as the owner's routes return it: the stored record,
// plus whether the contact is a person ("individual") or an organisation
// ("organization").
//
// The kind is not stored on the contact. It is read from what this agent
// recorded when the contact's address was resolved (witness.ContactMeta), the
// same record the witnessing boundary decides from, so the two can never
// disagree. It is the contact's own unverified claim, normalised: anything but
// the two known kinds, or a contact whose address was never resolved, is empty,
// which means unknown and is neither kind.
type contactView struct {
	store.ContactRecord
	EntityType string `json:"entity_type,omitempty"`
}

func (s *CoreServer) viewOfContact(c store.ContactRecord) contactView {
	v := contactView{ContactRecord: c}
	if s.WitnessService != nil {
		if meta, _ := s.WitnessService.ContactMetaFor(c.AID); meta != nil {
			v.EntityType = string(witness.NormaliseEntityType(meta.EntityType))
		}
	}
	return v
}

func (s *CoreServer) viewsOfContacts(cs []store.ContactRecord) []contactView {
	out := make([]contactView, 0, len(cs))
	for _, c := range cs {
		out = append(out, s.viewOfContact(c))
	}
	return out
}
