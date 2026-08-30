package server

import (
	"testing"
)

// The identity that will claim a machine exists before anybody asks for one.
//
// A machine is told who may claim it before it starts, and refuses everybody
// else. So the identity has to exist earlier than the request that creates the
// machine. Minting it at the moment of claiming produced a second, different
// identity the machine had never been told to expect: it refused its own owner,
// and no amount of rescanning could recover.
//
// The route that used to be the only way in is now a thin caller of this, so
// that the same minting can happen when somebody agrees to own an organisation
// -- the only moment their device is in the conversation beforehand.
func TestAnIdentityToClaimWithCanBeMintedWithoutARequest(t *testing.T) {
	s := adoptingOwner(t)

	aid, oobi, err := s.mintAnIdentityToClaimAMachineWith()
	if err != nil {
		t.Fatalf("could not mint an identity to claim a machine with: %v", err)
	}
	if aid == "" {
		t.Fatal("minted nothing")
	}
	if oobi == "" {
		t.Fatal("minted an identity nobody could resolve")
	}

	// Recorded, not handed out and taken back. Adoption looks the index up; an
	// identity whose index was lost can never be re-derived, which means never
	// signing to that machine again -- no rotation, no revocation, no recovery.
	if _, ok, err := s.DataStore.MachineOwnerIndex(aid); err != nil || !ok {
		t.Fatalf("the derivation index was not recorded, so this identity could never "+
			"be used again (found=%v, err=%v)", ok, err)
	}
}

// Two machines must not share an identity, or whoever provisioned both can join
// them -- which is the correlation the pairwise scheme exists to prevent.
func TestEachMachineGetsAnIdentityOfItsOwn(t *testing.T) {
	s := adoptingOwner(t)

	first, _, err := s.mintAnIdentityToClaimAMachineWith()
	if err != nil {
		t.Fatalf("first mint failed: %v", err)
	}
	second, _, err := s.mintAnIdentityToClaimAMachineWith()
	if err != nil {
		t.Fatalf("second mint failed: %v", err)
	}
	if first == second {
		t.Fatal("two machines would be claimed by the same identity, so the party that " +
			"provisioned both could tell they belong to one person")
	}
}
