package watcher

import (
	"context"
	"strings"
	"testing"
)

// A peer the boundary refuses is never contacted at all — so it is not even
// told which identity was being asked about, which is the thing worth
// protecting. A watcher learns the verifier's interests simply by being asked.
func TestARefusedPeerIsNeverContacted(t *testing.T) {
	var asked int32
	var got KelCheckRequest
	p := recordingPeer(t, &asked, &got)
	s := contactService(t, p.URL)
	s.PeerAllowed = func(peerURL string) bool { return false }
	outcomes, _ := s.crossCheckPeers(context.Background(), "EAlice", 0, "Edigest", p.URL+"/public/oobi/EAlice")
	if asked != 0 || len(outcomes) != 0 {
		t.Fatalf("a peer the boundary refuses was contacted: asked=%d outcomes=%+v", asked, outcomes)
	}
	if err := s.checkPeerAllowed(p.URL); err == nil || !strings.Contains(err.Error(), "do not watch for one another") {
		t.Fatalf("the refusal does not explain itself: %v", err)
	}
}

// No boundary configured means no restriction — a build with no notion of
// entity kind, or a test, behaves as before.
func TestNoBoundaryMeansNoRestriction(t *testing.T) {
	s := &Service{}
	if err := s.checkPeerAllowed("https://anyone.example"); err != nil {
		t.Fatalf("an unconfigured boundary refused a peer: %v", err)
	}
}

// An allowed peer passes the gate. It still has to be reachable, which is a
// different failure and not this gate's business.
func TestAnAllowedPeerPassesTheGate(t *testing.T) {
	s := &Service{PeerAllowed: func(string) bool { return true }}
	if err := s.checkPeerAllowed("https://a-peer.example"); err != nil {
		t.Fatalf("an allowed peer was refused: %v", err)
	}
}
