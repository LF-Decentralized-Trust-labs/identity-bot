package watcher

import (
	"context"
	"strings"
)

// Choosing which peers to cross-check with.
//
// The point of asking a peer is that it is not the party you are verifying and
// not the service they pay: a contact that holds the same digest shows the
// hosted watcher is the odd one out. It is asked only where that answer changes
// what happens (see VerifyKel), because asking tells it whom this agent deals
// with.
//
// Selection is deliberately narrow. A peer is a contact the owner chose, must be
// reachable when asked, and must be of the same kind: an organization watching
// for individuals accumulates a view of many people's activity, and an individual
// watching for an organization is drawn into business it has no standing in.
// Registered watcher services are not asked here; they answer the digest query
// (L2), and a cross-check is answered only for a contact.

// PeerWatcher is a contact the owner chose to cross-check with.
type PeerWatcher struct {
	// AID identifies the contact; URL is where its public watcher routes live.
	AID string
	URL string
}

// PeerWatcherSource supplies the peers available for a cross-check.
//
// Left nil where an agent has no way to choose them — a build with no contacts,
// or a test. Nil means no L3, which is reported as such rather than silently
// treated as agreement.
type PeerWatcherSource func() []PeerWatcher

// peers returns the peers to ask about one identity, or nothing when none are
// configured, the owner turned peer cross-checks off, or none plausibly knows it.
//
// sourceURL is where this agent met the identity's log this time.
func (s *Service) peers(aid, sourceURL string) []PeerWatcher {
	if s.PeerWatchers == nil || !s.PeerWatchEnabled() {
		return nil
	}
	// Read once, not once per peer.
	var seenAt []string
	if s.Store != nil {
		if recs, err := s.Store.listFirstSeen(aid); err == nil {
			for _, r := range recs {
				seenAt = append(seenAt, r.SourceURL)
			}
		}
	}
	var out []PeerWatcher
	for _, p := range s.PeerWatchers() {
		if p.URL == "" {
			continue
		}
		// The boundary is applied here as well as by the source, so a source
		// that has not applied it cannot widen who gets asked.
		if s.checkPeerAllowed(p.URL) != nil {
			continue
		}
		if !peerMayKnow(p, aid, sourceURL, seenAt) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// peerMayKnow says whether asking this peer about aid is worth what it tells
// them. A contact is asked only about an identity it plausibly knows: it is where
// this agent first met the identity's log (this time, or an earlier one in
// seenAt). It is never asked about itself: that contact is the identity, and an
// identity cannot corroborate its own log. Asking anybody else would only tell
// them whom we are dealing with.
func peerMayKnow(p PeerWatcher, aid, sourceURL string, seenAt []string) bool {
	if p.AID != "" && p.AID == aid {
		return false
	}
	if sameBase(p.URL, sourceURL) {
		return true
	}
	for _, u := range seenAt {
		if sameBase(p.URL, u) {
			return true
		}
	}
	return false
}

// sameBase reports whether a URL lies under a peer's base address: the address
// itself or a path below it, never one that merely starts with the same letters.
func sameBase(base, u string) bool {
	base = strings.TrimRight(base, "/")
	return base != "" && u != "" && (u == base || strings.HasPrefix(u, base+"/"))
}

// crossCheckPeers asks each peer whether it holds the same digest.
//
// Every outcome is recorded, including the ones that answer nothing. A peer
// that is unreachable, or that does not match, has not agreed with anybody —
// and counting silence as agreement is how a verifier convinces itself it has
// corroboration it does not have. A peer answers only match or no match, so
// "no_match" covers a different history and no history alike and is never
// counted as a disagreement.
func (s *Service) crossCheckPeers(ctx context.Context, aid string, seq int, digest, sourceURL string) (outcomes []SourceOutcome, agreed int) {
	for _, p := range s.peers(aid, sourceURL) {
		req, err := s.signedRequest(p.AID, p.URL, aid, seq, digest)
		if err != nil {
			// Not asked at all, so nothing was disclosed.
			outcomes = append(outcomes, SourceOutcome{Type: "L3", URL: p.URL, Outcome: "unavailable"})
			continue
		}
		resp, err := s.L3.CrossCheck(ctx, p.URL, req)
		switch {
		case err != nil:
			outcomes = append(outcomes, SourceOutcome{Type: "L3", URL: p.URL, Outcome: "unavailable"})
		case resp.Match:
			agreed++
			outcomes = append(outcomes, SourceOutcome{Type: "L3", URL: p.URL, Outcome: "match"})
		default:
			outcomes = append(outcomes, SourceOutcome{Type: "L3", URL: p.URL, Outcome: "no_match"})
		}
	}
	return outcomes, agreed
}
