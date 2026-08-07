package server

import (
	"strings"
	"testing"

	"identity-agent-core/didcomm"
)

func ownerDID(t *testing.T, aid string) *didcomm.DID {
	t.Helper()
	ks, err := didcomm.GenerateKeySet(aid)
	if err != nil {
		t.Fatal(err)
	}
	did, err := ks.DID()
	if err != nil {
		t.Fatal(err)
	}
	return did
}

// The gap this closes: after adoption the two parties had never exchanged
// encryption keys, so the first private request between them was refused for
// exactly the pair the feature exists to serve.
func TestAdoptionLeavesTheOwnerReachablePrivately(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	did := ownerDID(t, "EOWNER")

	if err := s.rememberPeerFromAdoption(did, "https://owner.example"); err != nil {
		t.Fatalf("the owner was not remembered: %v", err)
	}

	didcommMu.Lock()
	peer, known := s.loadPeers()["EOWNER"]
	didcommMu.Unlock()
	if !known {
		t.Fatal("the owner is not a peer after adoption, so nothing can be sealed to them")
	}
	if peer.DID.X25519 != did.X25519 {
		t.Error("the stored keys are not the ones the owner presented")
	}
	// Stored in the one shape both readers expect, whichever form arrived.
	if peer.Endpoint != "https://owner.example/didcomm" {
		t.Errorf("endpoint stored as %q", peer.Endpoint)
	}
}

// Adoption happens once. A second one carrying different keys for the same
// identity is either a mistake or somebody installing their own keys in place
// of the owner's, and overwriting quietly makes the second case invisible.
func TestASecondAdoptionCannotReplaceTheOwnersKeys(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	if err := s.rememberPeerFromAdoption(ownerDID(t, "EOWNER"), "https://owner.example"); err != nil {
		t.Fatal(err)
	}
	err := s.rememberPeerFromAdoption(ownerDID(t, "EOWNER"), "https://attacker.example")
	if err == nil {
		t.Fatal("a second set of keys replaced the owner's")
	}
	if !strings.Contains(err.Error(), "already holds different keys") {
		t.Errorf("the reason is unclear: %v", err)
	}
}

// Keys that cannot be used must be refused as they arrive, not when the owner
// is next trying to do something.
func TestUnusableOwnerKeysAreRefusedOnArrival(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	good := ownerDID(t, "EOWNER")

	for name, did := range map[string]*didcomm.DID{
		"nothing at all": nil,
		"no identity":    {AID: "", X25519: good.X25519},
		"truncated key":  {AID: "EOWNER", Ed: good.Ed, Dsa: good.Dsa, X25519: "AAAA", MlKem: good.MlKem, Suite: didcomm.CipherSuite},
		"unknown suite":  {AID: "EOWNER", Ed: good.Ed, Dsa: good.Dsa, X25519: good.X25519, MlKem: good.MlKem, Suite: "SOMETHING-ELSE"},
	} {
		if err := s.rememberPeerFromAdoption(did, "https://owner.example"); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// Re-presenting the SAME keys must not fail — an adoption retried after a
// dropped response is an ordinary thing, and refusing it would strand a box
// that is otherwise correctly adopted.
func TestRepeatingTheSameKeysIsNotAnError(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	did := ownerDID(t, "EOWNER")
	if err := s.rememberPeerFromAdoption(did, "https://owner.example"); err != nil {
		t.Fatal(err)
	}
	if err := s.rememberPeerFromAdoption(did, "https://owner.example"); err != nil {
		t.Fatalf("a retried adoption with the same keys was refused: %v", err)
	}
}
