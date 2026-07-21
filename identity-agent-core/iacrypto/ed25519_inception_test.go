package iacrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

// The plain ed25519 builder must produce a real self-addressing AID and a
// complete event map (regression: wireToInceptionMap's hybrid-anchor indexing
// panicked on plain events).
func TestBuildEd25519Inception(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	nextPub, _, _ := ed25519.GenerateKey(rand.Reader)
	res, err := BuildEd25519Inception(pub, nextPub)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.HasPrefix(res.AID, "E") || len(res.AID) != 44 {
		t.Fatalf("AID not a Blake3 SAID: %q", res.AID)
	}
	if res.AID != res.SAID {
		t.Fatalf("self-addressing violated: aid=%q said=%q", res.AID, res.SAID)
	}
	if res.InceptionEvent["t"] != "icp" || res.InceptionEvent["i"] != res.AID {
		t.Fatalf("event malformed: %+v", res.InceptionEvent)
	}
	// Deterministic: same keys → same AID.
	res2, _ := BuildEd25519Inception(pub, nextPub)
	if res2.AID != res.AID {
		t.Fatalf("non-deterministic AID")
	}
}
