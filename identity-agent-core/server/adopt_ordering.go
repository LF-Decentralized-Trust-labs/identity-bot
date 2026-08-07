package server

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"identity-agent-core/iacrypto"
	"identity-agent-core/secureenclave"
)

// checkOfferBeforeDelegating decides whether a box may be vouched for.
//
// Everything here has to happen before the delegation is issued, because after
// that there is nothing left to decide: the owner's signature over the box's
// keys exists, it verifies, and any party checking the chain later will find it
// sound. A check that runs afterwards can only discover that the owner already
// said something they did not mean.
//
// acceptableMeasurement decides whether the software the box launched is
// software this owner accepts. Which measurements those are is a question about
// who publishes and approves them, so it is answered elsewhere and passed in.
func checkOfferBeforeDelegating(offer *pairingBeginResponse, allowUnattested bool,
	acceptableMeasurement func([]byte) bool) error {

	if offer.Attestation == "" {
		if allowUnattested {
			// A deliberate choice, so it proceeds — and says so, because an
			// unattested box is a different thing from a sealed one and the
			// difference should not be discoverable only by reading code.
			return nil
		}
		return fmt.Errorf("this box did not prove what it is, and adopting it anyway has to be " +
			"asked for: a machine with no attestation may be an ordinary computer, or may be a " +
			"sealed one whose proof was removed in transit, and those look the same from here. " +
			"Send allow_unattested if you know which")
	}

	raw, err := base64.StdEncoding.DecodeString(offer.Attestation)
	if err != nil {
		return fmt.Errorf("this box's attestation could not be read: %w", err)
	}
	report, err := secureenclave.ParseSNPReport(raw)
	if err != nil {
		return fmt.Errorf("this box's attestation is not usable: %w", err)
	}

	// The report must be about THESE keys. Without this it says only that some
	// sealed machine exists somewhere, which is true of every sealed machine
	// and says nothing about the one being adopted — a genuine report from any
	// of them would pass.
	expected, err := iacrypto.PairingOfferBinding(offer.PublicKey, offer.NextPublicKey)
	if err != nil {
		return fmt.Errorf("this box's offer is incomplete: %w", err)
	}
	if !bytes.Equal(report.ReportData, secureenclave.BindReportData(expected)) {
		return fmt.Errorf("this box's hardware vouched for different keys than the ones it " +
			"offered, so the keys did not come from the machine the proof describes")
	}

	if report.DebugAllowed() {
		return fmt.Errorf("this box was started in a state where whoever runs the hardware can " +
			"read its memory, so nothing it holds would be private")
	}

	if acceptableMeasurement == nil {
		return fmt.Errorf("this owner has no statement of which software is acceptable, and " +
			"treating that as 'any' would adopt a box running anything")
	}
	if !acceptableMeasurement(report.Measurement) {
		return fmt.Errorf("this box launched software this owner has not accepted")
	}
	return nil
}

// acceptableMeasurement answers whether this owner accepts the software a box
// launched.
//
// The list of measurements an owner will accept has to come from somewhere, and
// nothing publishes one yet. Rather than invent an answer, this reports that
// there is no policy — which the caller above turns into a refusal, because a
// missing policy read as "accept anything" would make every other check here
// decorative.
//
// The deliberate consequence: adopting a sealed box requires either a
// measurement policy or an explicit allow_unattested, and both are visible
// choices. That is the right failure while the question of who signs the
// measurement list is open, and it is the hook that question plugs into when it
// is answered.
func (s *CoreServer) acceptableMeasurement(measurement []byte) bool {
	if len(s.AcceptedMeasurements) == 0 {
		return false
	}
	for _, allowed := range s.AcceptedMeasurements {
		if bytes.Equal(allowed, measurement) {
			return true
		}
	}
	return false
}
