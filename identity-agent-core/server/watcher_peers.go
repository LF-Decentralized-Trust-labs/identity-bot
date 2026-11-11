package server

import (
	"strings"

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
// Which contacts are asked is the owner's choice (watcher.ChosenPeers, at most
// watcher.MaxChosenPeers), and the owner can turn peer checks off altogether
// (watcher.PeerWatchEnabled, applied where peers are used). A contact is further
// asked only about identities it plausibly knows (watcher.peerMayKnow), and the
// request is signed. See peer_settings.go.
//
// Registered watcher services are not peers here: they are consulted for their
// digest (L2), and a cross-check is answered only for a contact.
func (s *CoreServer) peerWatchers() []watcher.PeerWatcher {
	var out []watcher.PeerWatcher
	seen := map[string]bool{}

	if s.DataStore == nil || s.WitnessService == nil || s.WatcherService == nil {
		return out
	}
	// Only contacts the owner chose, and never more than a handful: every one
	// asked learns whom this agent is checking on.
	chosen := map[string]bool{}
	for _, aid := range s.WatcherService.ChosenPeers() {
		chosen[aid] = true
	}
	if len(chosen) == 0 {
		return out
	}
	ours := witness.NormaliseEntityType(s.ourEntityType())
	contacts, err := s.DataStore.GetContacts()
	if err != nil {
		return out
	}
	for _, c := range contacts {
		if c.Status != "accepted" || c.OobiURL == "" || !chosen[c.AID] {
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
