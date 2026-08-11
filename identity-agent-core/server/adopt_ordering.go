package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

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
	acceptableMeasurement func([]byte) bool, verifyChain func([]byte) error) error {

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

	// And last, the check that makes the rest of them evidence.
	//
	// Everything above reads fields out of the report and compares them. A
	// report is 1184 bytes that anything can produce: the measurement is a
	// value its author chooses, so software emulating a sealed machine passes
	// every check so far. The signature, verified back to AMD's root, is what
	// separates "this machine says it is sealed" from "this machine is sealed".
	//
	// Left until last on purpose. It is the only step that goes to the network,
	// and there is no reason to ask AMD about a report that already failed on
	// its own contents.
	//
	// Deliberately not the operator's verification. The host running the
	// instance verifies chains too, and that establishes nothing for an owner:
	// it is the party a sealed VM exists to exclude, vouching for itself. This
	// runs on the owner's own machine, against AMD, or it is not a check.
	if verifyChain == nil {
		return fmt.Errorf("this owner cannot check whether the proof came from real AMD " +
			"hardware, and a proof nobody checked is a claim")
	}
	if err := verifyChain(raw); err != nil {
		// An unreachable service is not a forgery. Kept separate because the
		// responses differ: a bad signature means this machine is not what it
		// says and must not be adopted, while an outage means nothing is known
		// yet and the answer is to try again.
		if errors.Is(err, secureenclave.ErrChainUnavailable) {
			return fmt.Errorf("whether this box is genuine AMD hardware could not be "+
				"established, so it was not adopted rather than adopted on an unchecked "+
				"proof — this is usually temporary: %w", err)
		}
		return fmt.Errorf("this box's proof did not come from the AMD part it names: %w", err)
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

// verifySNPChain checks a report against AMD, on this machine.
//
// The verifier caches what it fetches, so it is built once and kept rather than
// made per adoption — otherwise adopting several instances would ask AMD for
// the same certificate each time, which is both wasteful and a good way to be
// rate-limited at the worst moment.
//
// AGENT_SNP_PRODUCT names the CPU family AMD's service knows. It defaults to
// Genoa, which also covers Siena and Bergamo — those are Zen 4c parts in the
// Genoa family, and asking for them by their own names returns 404.
func (s *CoreServer) verifySNPChain(report []byte) error {
	s.snpVerifierOnce.Do(func() {
		s.snpVerifier = secureenclave.NewAMDKDSVerifier(os.Getenv("AGENT_SNP_PRODUCT"))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return s.snpVerifier.VerifyChain(ctx, report)
}
