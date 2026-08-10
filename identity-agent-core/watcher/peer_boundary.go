package watcher

import "fmt"

// Which peers this agent may cross-check with.
//
// A watcher is chosen by the verifier rather than named in anybody's key event,
// so it carries none of a witness list's permanence. What it does carry is
// knowledge: a watcher learns which identities its subject is checking on, and
// whoever watches for many people accumulates that picture across all of them.
// The watchers an agent publishes as hints also disclose who has seen its log.
//
// So the same boundary applies as for witnesses. An organization watching for
// individuals builds a view of many people's activity; an individual watching
// for an organization is drawn into business it has no standing in. Peers are
// of the same kind, and registered watcher services are exempt because one
// serves a large population and so discloses almost nothing about its subject.
//
// An individual who wants an organization to watch for them is served by that
// organization registering as a watcher service — which makes the arrangement
// declared and population-wide, the property that makes it safe.

// PeerAllowed decides whether this agent may cross-check with a peer at a URL.
//
// Left nil where no boundary applies — a build with no notion of entity kind,
// or a test. When set, a peer it refuses is never contacted, so nothing is
// disclosed to it, not even the question.
type PeerAllowed func(peerURL string) bool

// checkPeerAllowed refuses a cross-check the boundary does not permit.
func (s *Service) checkPeerAllowed(peerURL string) error {
	if s.PeerAllowed == nil {
		return nil
	}
	if s.PeerAllowed(peerURL) {
		return nil
	}
	return fmt.Errorf("not cross-checking with %s: an individual and an organization do not "+
		"watch for one another, and this peer is neither the same kind nor a registered "+
		"watcher service", peerURL)
}
