package server

import (
	"encoding/base64"
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
	if err := checkOfferBeforeDelegating(offerWithReport(t, true, 0x11), false, acceptOnly(0x11)); err != nil {
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

	err := checkOfferBeforeDelegating(offer, false, acceptOnly(0x11))
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
	if err := checkOfferBeforeDelegating(offerWithReport(t, false, 0x11), false, acceptOnly(0x11)); err == nil {
		t.Fatal("a report unrelated to the offered keys was accepted")
	}
}

// No attestation is refused by default. It may be an ordinary computer, or a
// sealed one whose proof was stripped on the way — and those are identical from
// here, so which one it is has to be stated rather than assumed.
func TestAnUnattestedBoxIsRefusedUnlessAskedFor(t *testing.T) {
	bare := &pairingBeginResponse{PublicKey: "DKEY-ONE", NextPublicKey: "DKEY-TWO"}

	if err := checkOfferBeforeDelegating(bare, false, acceptOnly(0x11)); err == nil {
		t.Fatal("a box that proved nothing was adopted by default")
	}
	if err := checkOfferBeforeDelegating(bare, true, acceptOnly(0x11)); err != nil {
		t.Fatalf("adopting an unattested box on purpose was refused: %v", err)
	}
}

// Software the owner has not accepted is refused even when the box is
// genuinely sealed and genuinely holds the keys.
func TestSoftwareTheOwnerHasNotAcceptedIsNotAdopted(t *testing.T) {
	if err := checkOfferBeforeDelegating(offerWithReport(t, true, 0x99), false, acceptOnly(0x11)); err == nil {
		t.Fatal("a box running unapproved software was adopted")
	}
}

// No policy is not the same as accepting everything. Treating it as such would
// make every other check here decorative.
func TestNoMeasurementPolicyRefusesRatherThanAccepts(t *testing.T) {
	if err := checkOfferBeforeDelegating(offerWithReport(t, true, 0x11), false, nil); err == nil {
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

	if err := checkOfferBeforeDelegating(offer, false, acceptOnly(0x11)); err == nil {
		t.Fatal("a box whose memory can be read was adopted")
	}
	_ = secureenclave.ReportSize
}
