package server

import (
	"errors"
	"strings"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/secureenclave"
)

// A report shaped the way the hardware produces one, so the checks are
// exercised rather than described.
func syntheticReport(bindTo string, measurement byte) []byte {
	raw := make([]byte, secureenclave.ReportSize)
	copy(raw[0x50:], secureenclave.BindReportData(bindTo)) // REPORT_DATA
	for i := 0; i < secureenclave.MeasurementSize; i++ {
		raw[0x90+i] = measurement
	}
	for i := 0; i < secureenclave.ChipIDSize; i++ {
		raw[0x1A0+i] = 0x5A // CHIP_ID must not be masked
	}
	raw[0x2A0] = 0x01 // a signature must be present
	return raw
}

func anyMeasurement(_ []byte) bool { return true }

func offerFor(t *testing.T) (*boxIdentity, string) {
	t.Helper()
	box, err := newBoxIdentity("EOWNER")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := iacrypto.BoxKeyBindingForEvent(box.InceptionEvent)
	if err != nil {
		t.Fatal(err)
	}
	return box, binding
}

// The good case: hardware vouches for exactly the keys the identifier commits
// to, and the owner may sign.
func TestAnOfferBackedByTheHardwareMayBeSigned(t *testing.T) {
	box, binding := offerFor(t)
	err := CheckBoxOfferBeforeSigning(BoxOffer{
		InceptionEvent: box.InceptionEvent,
		Report:         syntheticReport(binding, 0x11),
	}, anyMeasurement)
	if err != nil {
		t.Fatalf("a sound offer was refused: %v", err)
	}
}

// THE ONE THAT MATTERS. A proxy or operator substitutes their own keys into the
// event on the way to the owner. The hardware still produces a genuine report —
// for the real machine's real keys. The owner must not sign.
func TestSubstitutedKeysAreRefusedEvenWithAGenuineReport(t *testing.T) {
	realBox, realBinding := offerFor(t)
	attacker, _ := offerFor(t)

	// The attacker's event, carrying the attacker's keys, presented alongside
	// the real machine's genuine attestation.
	err := CheckBoxOfferBeforeSigning(BoxOffer{
		InceptionEvent: attacker.InceptionEvent,
		Report:         syntheticReport(realBinding, 0x11),
	}, anyMeasurement)
	if err == nil {
		t.Fatal("an owner would have signed for keys the sealed machine does not hold")
	}
	if !errors.Is(err, ErrOfferUnverified) {
		t.Errorf("wrong error kind: %v", err)
	}
	_ = realBox
}

// Software the owner has not accepted must be refused even when everything else
// is perfect, or the check confirms a machine is sealed while saying nothing
// about what is sealed inside it.
func TestSoftwareTheOwnerHasNotAcceptedIsRefused(t *testing.T) {
	box, binding := offerFor(t)
	err := CheckBoxOfferBeforeSigning(BoxOffer{
		InceptionEvent: box.InceptionEvent,
		Report:         syntheticReport(binding, 0x99),
	}, func(m []byte) bool { return m[0] == 0x11 })
	if err == nil {
		t.Fatal("a machine running unapproved software was accepted")
	}
}

// No policy is not the same as any policy. Defaulting to "accept" here would
// make every other check decorative.
func TestNoPolicyIsRefusedRatherThanTreatedAsAny(t *testing.T) {
	box, binding := offerFor(t)
	if err := CheckBoxOfferBeforeSigning(BoxOffer{
		InceptionEvent: box.InceptionEvent,
		Report:         syntheticReport(binding, 0x11),
	}, nil); err == nil {
		t.Fatal("an offer was accepted with no statement of which software is acceptable")
	}
}

// An identity with no committed keys must not be signed: the keys could be
// changed afterwards and the signature would still verify.
func TestAnIdentifierThatCommitsToNoKeysIsRefused(t *testing.T) {
	_, binding := offerFor(t)
	err := CheckBoxOfferBeforeSigning(BoxOffer{
		InceptionEvent: map[string]interface{}{"t": "dip", "di": "EOWNER"},
		Report:         syntheticReport(binding, 0x11),
	}, anyMeasurement)
	if err == nil {
		t.Fatal("an identifier committing to no keys was accepted")
	}
}

// A machine that produced no attestation is not a sealed machine, whatever its
// event says.
func TestNoAttestationIsRefused(t *testing.T) {
	box, _ := offerFor(t)
	if err := CheckBoxOfferBeforeSigning(BoxOffer{InceptionEvent: box.InceptionEvent}, anyMeasurement); err == nil {
		t.Fatal("an offer with no attestation was accepted")
	}
}

// A report is cryptographically perfect and worth nothing if the hypervisor may
// read the guest's memory.
func TestADebuggableMachineIsRefused(t *testing.T) {
	box, binding := offerFor(t)
	raw := syntheticReport(binding, 0x11)
	raw[0x08+2] |= 0x08 // POLICY bit 19 — debug allowed
	if err := CheckBoxOfferBeforeSigning(BoxOffer{
		InceptionEvent: box.InceptionEvent, Report: raw,
	}, anyMeasurement); err == nil {
		t.Fatal("a machine whose memory can be read was accepted")
	}
}

// The published description of how the binding was computed must describe the
// binding that was actually used. It was fixed text naming the transport
// certificate, so once the binding became something else the description named
// a construction the report did not use — and a verifier following it would
// compute a value that cannot match and read the mismatch as tampering.
func TestThePublishedSchemeDescribesTheBindingActuallyUsed(t *testing.T) {
	box, _ := offerFor(t)
	s := &CoreServer{}

	// With no identity of its own, the old description still applies.
	if got := bindingScheme("something", s.bindingOver()); got == "" ||
		!strings.Contains(got, "certificate on this connection") {
		t.Errorf("without a machine identity the scheme should still name the transport key, got %q", got)
	}

	// With one, it must name the keys instead.
	s.boxIdentity = box
	got := bindingScheme("something", s.bindingOver())
	if strings.Contains(got, "certificate on this connection") {
		t.Errorf("the scheme still names the transport certificate after the binding moved: %q", got)
	}
	if !strings.Contains(got, "IA-BOX-KEYS-V1") {
		t.Errorf("the scheme does not name the construction actually used: %q", got)
	}

	// And what it binds must be the value a verifier recomputes from the event.
	expected, err := iacrypto.BoxKeyBindingForEvent(box.InceptionEvent)
	if err != nil {
		t.Fatal(err)
	}
	if s.attestationBinding() != expected {
		t.Error("the agent binds a different value than a verifier would recompute from its identifier")
	}
}
