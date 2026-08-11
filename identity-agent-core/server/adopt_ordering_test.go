package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/secureenclave"
)

func offerWithReport(t *testing.T, bindKeys bool, measurement byte) *pairingBeginResponse {
	t.Helper()
	offer := &pairingBeginResponse{PublicKey: "DKEY-ONE", NextPublicKey: "DKEY-TWO"}
	bound := "something-else"
	if bindKeys {
		b, err := iacrypto.PairingOfferBinding(offer.PublicKey, offer.NextPublicKey)
		if err != nil {
			t.Fatal(err)
		}
		bound = b
	}
	offer.Attestation = base64.StdEncoding.EncodeToString(syntheticReport(bound, measurement))
	return offer
}

func acceptOnly(m byte) func([]byte) bool {
	return func(got []byte) bool { return len(got) > 0 && got[0] == m }
}

// A box that proves it holds the keys it offered, running software the owner
// accepts, may be vouched for.
func TestABoxThatProvesItselfMayBeAdopted(t *testing.T) {
	if err := checkOfferBeforeDelegating(offerWithReport(t, true, 0x11), false, acceptOnly(0x11), chainAlwaysGenuine); err != nil {
		t.Fatalf("a sound box was refused: %v", err)
	}
}

// THE ONE THAT MATTERS. Something between the owner and the box swaps the
// offered keys. The attestation is genuine — it is just about the real
// machine's real keys, not the ones that arrived. Signing now would produce a
// delegation that verifies and names somebody else's machine.
func TestSubstitutedOfferKeysAreRefused(t *testing.T) {
	offer := offerWithReport(t, true, 0x11)
	offer.PublicKey = "DATTACKER-KEY" // swapped in transit; report untouched

	err := checkOfferBeforeDelegating(offer, false, acceptOnly(0x11), chainAlwaysGenuine)
	if err == nil {
		t.Fatal("the owner would have delegated to keys the sealed machine does not hold")
	}
	if !strings.Contains(err.Error(), "different keys") {
		t.Errorf("the reason is unclear: %v", err)
	}
}

// A report that vouches for nothing in this offer proves only that some sealed
// machine exists somewhere — true of every sealed machine, and no statement
// about this one.
func TestAReportAboutSomethingElseIsRefused(t *testing.T) {
	if err := checkOfferBeforeDelegating(offerWithReport(t, false, 0x11), false, acceptOnly(0x11), chainAlwaysGenuine); err == nil {
		t.Fatal("a report unrelated to the offered keys was accepted")
	}
}

// No attestation is refused by default. It may be an ordinary computer, or a
// sealed one whose proof was stripped on the way — and those are identical from
// here, so which one it is has to be stated rather than assumed.
func TestAnUnattestedBoxIsRefusedUnlessAskedFor(t *testing.T) {
	bare := &pairingBeginResponse{PublicKey: "DKEY-ONE", NextPublicKey: "DKEY-TWO"}

	if err := checkOfferBeforeDelegating(bare, false, acceptOnly(0x11), chainAlwaysGenuine); err == nil {
		t.Fatal("a box that proved nothing was adopted by default")
	}
	if err := checkOfferBeforeDelegating(bare, true, acceptOnly(0x11), chainAlwaysGenuine); err != nil {
		t.Fatalf("adopting an unattested box on purpose was refused: %v", err)
	}
}

// Software the owner has not accepted is refused even when the box is
// genuinely sealed and genuinely holds the keys.
func TestSoftwareTheOwnerHasNotAcceptedIsNotAdopted(t *testing.T) {
	if err := checkOfferBeforeDelegating(offerWithReport(t, true, 0x99), false, acceptOnly(0x11), chainAlwaysGenuine); err == nil {
		t.Fatal("a box running unapproved software was adopted")
	}
}

// No policy is not the same as accepting everything. Treating it as such would
// make every other check here decorative.
func TestNoMeasurementPolicyRefusesRatherThanAccepts(t *testing.T) {
	if err := checkOfferBeforeDelegating(offerWithReport(t, true, 0x11), false, nil, chainAlwaysGenuine); err == nil {
		t.Fatal("a box was adopted with no statement of acceptable software")
	}
	s := &CoreServer{}
	if s.acceptableMeasurement([]byte{0x11}) {
		t.Error("an empty policy accepted a measurement")
	}
	s.AcceptedMeasurements = [][]byte{{0x11}}
	if !s.acceptableMeasurement([]byte{0x11}) {
		t.Error("a listed measurement was refused")
	}
	if s.acceptableMeasurement([]byte{0x12}) {
		t.Error("an unlisted measurement was accepted")
	}
}

// A machine whose memory the operator can read holds nothing privately,
// however genuine its report.
func TestADebuggableBoxIsNotAdopted(t *testing.T) {
	offer := offerWithReport(t, true, 0x11)
	raw, _ := base64.StdEncoding.DecodeString(offer.Attestation)
	raw[0x08+2] |= 0x08 // POLICY bit 19
	offer.Attestation = base64.StdEncoding.EncodeToString(raw)

	if err := checkOfferBeforeDelegating(offer, false, acceptOnly(0x11), chainAlwaysGenuine); err == nil {
		t.Fatal("a box whose memory can be read was adopted")
	}
	_ = secureenclave.ReportSize
}

// chainAlwaysGenuine stands in for AMD for the tests above, each of which was
// written to check one earlier step and should still fail on that step rather
// than on a network call. The chain check has its own tests below.
func chainAlwaysGenuine([]byte) error { return nil }

// The check that turns every other check into evidence.
//
// Everything before this reads fields out of the report and compares them, and
// a report is 1184 bytes that anything can produce — the measurement is a value
// its author chooses. Software emulating a sealed machine passes every earlier
// step. Only the signature, verified back to AMD's root, distinguishes a
// machine that is sealed from one that says so.
func TestAReportThatDidNotComeFromAMDIsRefused(t *testing.T) {
	forged := func([]byte) error {
		return fmt.Errorf("the report's signature does not verify against the certificate " +
			"AMD issued for that part")
	}
	err := checkOfferBeforeDelegating(offerWithReport(t, true, 0x11), false, acceptOnly(0x11), forged)
	if err == nil {
		t.Fatal("a report whose signature does not verify was accepted, so a software " +
			"emulator claiming any measurement would be adopted")
	}
	if strings.Contains(err.Error(), "could not be established") {
		t.Errorf("a forgery was reported as an outage, which invites a retry that will "+
			"never succeed: %v", err)
	}
}

// An owner with no way to check is not an owner who checked.
func TestNoChainVerifierIsRefused(t *testing.T) {
	if err := checkOfferBeforeDelegating(offerWithReport(t, true, 0x11), false, acceptOnly(0x11), nil); err == nil {
		t.Fatal("adoption proceeded with nothing able to check the proof's provenance")
	}
}

// AMD being unreachable is not evidence of anything, and must not be reported
// as though it were. The responses differ: a forgery means never adopt this
// machine, an outage means try again later.
func TestAnUnreachableServiceIsNotAForgery(t *testing.T) {
	unavailable := func([]byte) error {
		return fmt.Errorf("%w: dial tcp: lookup kdsintf.amd.com: no such host",
			secureenclave.ErrChainUnavailable)
	}
	err := checkOfferBeforeDelegating(offerWithReport(t, true, 0x11), false, acceptOnly(0x11), unavailable)
	if err == nil {
		t.Fatal("an unverifiable proof was adopted; unknown provenance is not good provenance")
	}
	if !strings.Contains(err.Error(), "could not be established") {
		t.Errorf("an outage should say the answer is unknown, not that the box is a "+
			"forgery: %v", err)
	}
	if !errors.Is(err, secureenclave.ErrChainUnavailable) {
		t.Error("callers cannot distinguish an outage from a forgery without the wrapped error")
	}
}

// The chain is checked last, so an offer that already failed on its own
// contents never reaches the network. Otherwise every malformed or hostile
// offer would cost a round trip to AMD, which is both slow and a way to be
// rate-limited by somebody else's traffic.
func TestTheNetworkIsNotConsultedForAnOfferThatAlreadyFailed(t *testing.T) {
	called := false
	watch := func([]byte) error { called = true; return nil }

	offer := offerWithReport(t, true, 0x11)
	offer.PublicKey = "DATTACKER-KEY" // fails the binding check, well before the chain
	if err := checkOfferBeforeDelegating(offer, false, acceptOnly(0x11), watch); err == nil {
		t.Fatal("a substituted offer was accepted")
	}
	if called {
		t.Error("AMD was consulted about an offer that had already failed its own checks")
	}
}
