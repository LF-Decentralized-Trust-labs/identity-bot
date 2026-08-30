package server

import (
	"strings"
	"testing"
)

// The identity that claims a machine and the identity that owns what it founds
// are two different things, and the second is proved rather than asserted.
//
// ADR-038: whoever provisioned the machine was told which identity would claim
// it. Sealing that same identity as the owner would let them recognise their own
// customer in a published inception event — so an owner may be named separately.
// An owner named at inception can never be replaced, which is why naming one
// without proof is refused rather than trusted.

func TestNamingAnOwnerWithoutProvingItIsRefused(t *testing.T) {
	machine, _, _ := pairableComputer(t)

	for _, c := range []struct {
		what  string
		owner *foundedOwner
		says  string
	}{
		{
			"no identity at all",
			&foundedOwner{Signature: "x", KEL: []map[string]interface{}{{}}},
			"which identity",
		},
		{
			"an identity with no signature",
			&foundedOwner{AID: "EFakeOwner", KEL: []map[string]interface{}{{}}},
			"asserts control rather than proving it",
		},
		{
			"a signature with no key log to check it against",
			&foundedOwner{AID: "EFakeOwner", Signature: "sig"},
			"nothing to check",
		},
	} {
		t.Run(c.what, func(t *testing.T) {
			err := machine.verifyTheOwnerBeingSealed(c.owner, "challenge", "code", "offered")
			if err == nil {
				t.Fatalf("%s was accepted as an owner; it would have been sealed into an "+
					"inception event that can never be rewritten", c.what)
			}
			if !strings.Contains(err.Error(), c.says) {
				t.Fatalf("refused, but not in words somebody could act on: %v", err)
			}
		})
	}
}

// A key log that does not prove its own authorship establishes nothing about who
// controls the identity, so it cannot support naming that identity as an owner.
func TestAnOwnerWhoseKeyLogProvesNothingIsRefused(t *testing.T) {
	machine, _, _ := pairableComputer(t)

	err := machine.verifyTheOwnerBeingSealed(&foundedOwner{
		AID:       "EDefinitelyNotARealIdentifier",
		Signature: "not-a-signature",
		KEL:       []map[string]interface{}{{"t": "icp", "i": "EDefinitelyNotARealIdentifier"}},
	}, "challenge", "code", "offered")

	if err == nil {
		t.Fatal("an owner was sealed on a key log that proves nothing about who holds it")
	}
}

// A machine that cannot check a key log refuses, rather than sealing an owner it
// took on trust. Half a check is not a lesser version of the check.
func TestAMachineThatCannotCheckRefusesToSealAnOwner(t *testing.T) {
	machine, _, _ := pairableComputer(t)
	machine.KeriDriver = nil

	err := machine.verifyTheOwnerBeingSealed(&foundedOwner{
		AID:       "ESomeIdentity",
		Signature: "sig",
		KEL:       []map[string]interface{}{{"t": "icp"}},
	}, "challenge", "code", "offered")

	if err == nil || !strings.Contains(err.Error(), "cannot verify a key log") {
		t.Fatalf("expected a refusal naming its own cause; got %v", err)
	}
}
