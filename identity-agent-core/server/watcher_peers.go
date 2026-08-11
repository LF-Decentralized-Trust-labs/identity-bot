package server

import (
	"strings"

	"identity-agent-core/provider"
	"identity-agent-core/watcher"
	"identity-agent-core/witness"
)

// Which peers this agent will compare notes with about somebody else's key log.
//
// Peer watching is what makes duplicity a property of the network rather than
// one agent's opinion: two agents that have both seen an identity compare a
// digest and share nothing else. Without peers the pipeline is this agent's own
// memory plus one service, which is one operator agreeing with itself.
//
// The selection mirrors witnesses because the same things are true of both. A
// peer must be somebody there is already a relationship with, must be running
// something that answers when asked, and must be of the same kind — an
// organization watching for individuals accumulates a picture of many people's
// activity, and an individual watching for an organization is drawn into
// business it has no standing in.
//
// Registered watcher services are included and marked as services. They are
// exempt from the same-kind rule for the reason that exemption exists at all:
// one serves a large population, so asking it discloses little.
func (s *CoreServer) peerWatchers() []watcher.PeerWatcher {
	var out []watcher.PeerWatcher
	seen := map[string]bool{}

	// Registered watcher services first — they are the ones that answer
	// reliably, and they are available before anybody has contacts.
	if s.Providers != nil {
		for _, p := range s.Providers.Offering(provider.CapabilityWatcher) {
			for _, e := range p.EndpointsFor(provider.CapabilityWatcher) {
				if e.URL == "" || seen[e.URL] {
					continue
				}
				seen[e.URL] = true
				out = append(out, watcher.PeerWatcher{AID: e.AID, URL: e.URL, Service: true})
			}
		}
	}

	if s.DataStore == nil || s.WitnessService == nil {
		return out
	}
	ours := witness.NormaliseEntityType(s.ourEntityType())
	contacts, err := s.DataStore.GetContacts()
	if err != nil {
		return out
	}
	for _, c := range contacts {
		if c.Status != "accepted" || c.OobiURL == "" {
			continue
		}
		base := peerBaseURL(c.OobiURL)
		if base == "" || seen[base] {
			continue
		}
		meta, _ := s.WitnessService.ContactMetaFor(c.AID)
		if meta == nil {
			// Nothing recorded about this contact, so neither its kind nor
			// whether it can answer is known. Left out rather than guessed at,
			// and picked up the next time it is resolved.
			continue
		}
		// Must be running something that is there when asked. A contact
		// reachable only on a phone cannot answer a cross-check, and counting
		// it would mean treating an unreachable peer's silence as a source.
		if !witness.IsBackendEligible(meta.BackendType) {
			continue
		}
		if !witness.PeerAllowedAcross(ours, witness.NormaliseEntityType(meta.EntityType)) {
			continue
		}
		seen[base] = true
		out = append(out, watcher.PeerWatcher{AID: c.AID, URL: base})
	}
	return out
}

// peerBaseURL turns a contact's OOBI into the address its public watcher
// endpoints live under.
func peerBaseURL(oobi string) string {
	if idx := strings.Index(oobi, "/public/oobi/"); idx != -1 {
		return strings.TrimRight(oobi[:idx], "/")
	}
	return strings.TrimRight(oobi, "/")
}
