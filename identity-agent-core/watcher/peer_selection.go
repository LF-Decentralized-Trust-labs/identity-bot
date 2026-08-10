package watcher

import "context"

// Choosing which peers to cross-check with.
//
// The point of asking a peer at all is that it is not the party you are
// verifying and not the service they pay. Two agents that have both seen the
// same identity's log compare a digest and share nothing else; a disagreement
// is a duplicity signal the verifier evaluates itself. That only works if there
// are peers to ask, and until now nothing chose any — the pipeline queried its
// own memory and one commercial service, which is two sources with one operator
// behind the second.
//
// Selection is deliberately narrow. A peer must be somebody this agent already
// has a relationship with, must be reachable when asked, and must be of the
// same kind — an organization watching for individuals accumulates a view of
// many people's activity, and an individual watching for an organization is
// drawn into business it has no standing in. Registered watcher services are
// exempt from the last of those, because one serves a large population.

// PeerWatcher is somebody this agent may compare notes with.
type PeerWatcher struct {
	// AID identifies the peer; URL is where its public digest endpoint lives.
	AID string
	URL string
	// Service is true for a registered watcher service rather than a contact.
	// Recorded so a result can say whether corroboration came from peers or
	// from operators, which are different assurances.
	Service bool
}

// PeerWatcherSource supplies the peers available for a cross-check.
//
// Left nil where an agent has no way to choose them — a build with no contacts,
// or a test. Nil means no L3, which is reported as such rather than silently
// treated as agreement.
type PeerWatcherSource func() []PeerWatcher

// peers returns the peers to ask, or nothing when none are configured.
func (s *Service) peers() []PeerWatcher {
	if s.PeerWatchers == nil {
		return nil
	}
	var out []PeerWatcher
	for _, p := range s.PeerWatchers() {
		if p.URL == "" {
			continue
		}
		// The boundary is applied here as well as at CrossCheck, so a source
		// that has not applied it cannot widen who gets asked.
		if s.PeerAllowed != nil && !s.PeerAllowed(p.URL) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// crossCheckPeers asks each peer whether it holds the same digest.
//
// Every outcome is recorded, including the ones that answer nothing. A peer
// that is unreachable, or that has never seen this identity, has not agreed
// with anybody — and counting silence as agreement is how a verifier convinces
// itself it has corroboration it does not have.
func (s *Service) crossCheckPeers(ctx context.Context, aid string, seq int, digest string) (outcomes []SourceOutcome, agreed, disagreed int) {
	for _, p := range s.peers() {
		resp, err := s.L3.CrossCheck(ctx, p.URL, KelCheckRequest{AID: aid, Seq: seq, Digest: digest})
		switch {
		case err != nil:
			outcomes = append(outcomes, SourceOutcome{Type: "L3", URL: p.URL, Outcome: "unavailable"})
		case resp.OurDigest == nil:
			// Has never seen this identity, so it holds no digest to compare.
			// Not a disagreement — it is the absence of an opinion, and the two
			// must not collapse.
			outcomes = append(outcomes, SourceOutcome{Type: "L3", URL: p.URL, Outcome: "unknown"})
		case resp.Match:
			agreed++
			outcomes = append(outcomes, SourceOutcome{Type: "L3", URL: p.URL, Outcome: "match"})
		default:
			disagreed++
			outcomes = append(outcomes, SourceOutcome{Type: "L3", URL: p.URL, Outcome: "mismatch"})
			s.emit("kel_l3_escalation", map[string]interface{}{
				"aid": aid, "seq": seq, "peer": p.URL,
			})
		}
	}
	return outcomes, agreed, disagreed
}
