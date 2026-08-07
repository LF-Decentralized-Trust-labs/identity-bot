package server

import (
	"testing"

	"identity-agent-core/didcomm"
	"identity-agent-core/iacrypto"
)

// The property the whole design rests on: the keys the identifier commits to
// are the keys the machine will actually decrypt with. If the anchor described
// some other set, an identifier could vouch for keys nobody uses while the real
// ones were still fetched from whoever answered.
func TestTheAnchoredKeysAreTheKeysTheMachineWillUse(t *testing.T) {
	box, err := newBoxIdentity("EOWNER")
	if err != nil {
		t.Fatal(err)
	}

	anchoredX, anchoredKem, err := iacrypto.AnchoredAgreementKeys(box.InceptionEvent)
	if err != nil {
		t.Fatalf("the machine's own inception did not yield its keys: %v", err)
	}

	did, err := box.Current.DID()
	if err != nil {
		t.Fatal(err)
	}
	if err := did.MatchesAnchoredKeys(anchoredX, anchoredKem); err != nil {
		t.Fatalf("the keys this machine would hand out are not the ones its identifier "+
			"commits to: %v", err)
	}
	if did.AID != box.AID {
		t.Errorf("the keyset is labelled %s but the identity is %s", did.AID, box.AID)
	}
}

// Two machines must never share an identity. They generate independently, so
// this is really a check that nothing is derived from a fixed value.
func TestEveryMachineGetsItsOwnIdentity(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		box, err := newBoxIdentity("EOWNER")
		if err != nil {
			t.Fatal(err)
		}
		if seen[box.AID] {
			t.Fatalf("two machines produced the same identifier: %s", box.AID)
		}
		seen[box.AID] = true
	}
}

// The identity commits to the keys it will rotate into, so the successor has to
// exist now — and it must not be the current one, or the commitment promises a
// change to the key already in use.
func TestTheMachineCommitsToASuccessorItActuallyHolds(t *testing.T) {
	box, err := newBoxIdentity("EOWNER")
	if err != nil {
		t.Fatal(err)
	}
	if box.Next == nil {
		t.Fatal("no successor keys were kept, so this identity can never rotate")
	}
	cur, err := box.Current.DID()
	if err != nil {
		t.Fatal(err)
	}
	nxt, err := box.Next.DID()
	if err != nil {
		t.Fatal(err)
	}
	if cur.Ed == nxt.Ed || cur.X25519 == nxt.X25519 {
		t.Error("the successor keys are the current keys")
	}
}

// An identity that acts for somebody must know who before it is made, or it
// commits to keys with no statement of whose machine this is.
func TestAMachineWillNotMakeAnIdentityForNobody(t *testing.T) {
	if _, err := newBoxIdentity(""); err == nil {
		t.Fatal("a machine made an identity with no owner")
	}
}

// The event carries the delegator, so the owner signing it is signing a
// statement about their own machine — not a bare set of keys that could be
// re-presented as somebody else's.
func TestWhatTheOwnerSignsNamesThemselves(t *testing.T) {
	box, err := newBoxIdentity("EOWNER")
	if err != nil {
		t.Fatal(err)
	}
	if box.InceptionEvent["di"] != "EOWNER" {
		t.Errorf("the event the owner signs does not name them: %v", box.InceptionEvent["di"])
	}
	if box.InceptionEvent["t"] != "dip" {
		t.Errorf("the event is not a delegated inception: %v", box.InceptionEvent["t"])
	}
	var _ *didcomm.KeySet = box.Current
}
