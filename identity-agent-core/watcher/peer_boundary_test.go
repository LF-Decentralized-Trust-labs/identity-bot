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
	contacted := false
	s := &Service{
		PeerAllowed: func(peerURL string) bool { return false },
	}
	// If the boundary let this through it would attempt an HTTP request to an
	// address that does not exist, and fail differently.
	err := s.CrossCheck(context.Background(), "https://an-organization.example", "EAlice", 0, "Edigest")
	if err == nil {
		t.Fatal("a cross-check with a refused peer went ahead")
	}
	if !strings.Contains(err.Error(), "do not watch for one another") {
		t.Fatalf("the refusal does not explain itself: %v", err)
	}
	if contacted {
		t.Fatal("the refused peer was contacted anyway")
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
