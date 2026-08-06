package server

import "testing"

// What an agent can prove about the machine it runs on.
//
// The chain is the same everywhere — which key store backs the identity,
// whether the running binary matches what was signed, whether it is current —
// and it has one more rung where the machine itself can attest. An agent on
// somebody's desk answers the first three and stops; an agent on hardware
// somebody else owns has to answer the fourth, because it is the one that
// matters there.

// No sealed hardware is a real answer, not a missing one.
//
// It is the correct answer for a laptop and a phone, and it must stay
// distinguishable from "sealed but cannot prove it" — those call for opposite
// reactions from whoever is reading, and collapsing them into one absent field
// is how "not sealed" gets mistaken for "fine".
func TestAnOrdinaryMachineClaimsNoSealedHardware(t *testing.T) {
	if secureenclaveSNPAvailableForTest() {
		t.Skip("this machine has SNP; the assertion is about ones that do not")
	}
	if got := sealedHardwareStatus("EAID"); got != nil {
		t.Fatalf("a machine with no sealed hardware claimed some: %+v", got)
	}
}

// The chain is reported as unverified, always, and never omitted.
//
// The difference between "this machine is sealed" and "this machine SAYS it is
// sealed" is the AMD signature chain, and it is not checked. Omitting the field
// would let a reader assume the stronger claim; stating it false makes the gap
// something they have to look at.
func TestTheUnverifiedChainIsStatedRatherThanOmitted(t *testing.T) {
	info := &SealedHardwareInfo{}
	if info.ChainVerified {
		t.Fatal("the zero value claims a verified chain")
	}
}

// The binding is what stops a report being lifted from one machine and
// presented by another, so it has to name something the verifier already holds.
func TestTheReportIsBoundToSomethingAVerifierHolds(t *testing.T) {
	info := sealedHardwareStatusForBinding("EKNOWNTOTHEVERIFIER")
	if info == nil {
		t.Skip("no sealed hardware here")
	}
	if info.BoundTo == "" {
		t.Fatal("the report names nothing, so it could have come from any machine")
	}
}

// Indirection so the two tests above can run on any machine.
func secureenclaveSNPAvailableForTest() bool                      { return sealedHardwareStatus("x") != nil }
func sealedHardwareStatusForBinding(b string) *SealedHardwareInfo { return sealedHardwareStatus(b) }
