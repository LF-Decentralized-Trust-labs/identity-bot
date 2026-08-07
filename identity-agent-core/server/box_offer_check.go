package server

import (
	"bytes"
	"errors"
	"fmt"

	"identity-agent-core/iacrypto"
	"identity-agent-core/secureenclave"
)

// What an owner must establish before vouching for a machine.
//
// A machine offers an identity: here are my keys, here is who I say I act for,
// here is the event binding the two. Signing that event is what makes it real —
// it is the owner saying, in a log other people read, that this identifier is
// their machine and these are its keys.
//
// Which means signing it is irreversible in the way that matters. If the keys in
// that event are not the ones inside the sealed machine — if a proxy or an
// operator substituted their own on the way — then the owner has just given a
// cryptographic blessing to somebody else's keys, and every party who checks
// the chain afterwards will find it correct. The chain would be sound and point
// at the wrong machine.
//
// So the order is fixed and it is the whole design: verify the hardware, verify
// that the hardware vouches for THESE keys, and only then sign. An owner who
// signs first has verified nothing, because by then there is nothing left to
// decide.

// ErrOfferUnverified is returned whenever an offer must not be signed. The
// reason is wrapped for whoever reads it; the decision is the same either way.
var ErrOfferUnverified = errors.New("this machine's offer was not verified, so it must not be signed")

// BoxOffer is what a machine presents to its prospective owner.
type BoxOffer struct {
	// InceptionEvent is the event the owner is asked to sign. The keys are
	// inside it, which is why signing it means something.
	InceptionEvent map[string]interface{}
	// Report is the raw attestation report from the machine's hardware.
	Report []byte
}

// CheckBoxOfferBeforeSigning establishes that an offer is safe to sign.
//
// Returns nil only when every check passed. Any failure is a refusal — there is
// no partial result and no "sign it anyway", because a caller holding a warning
// and a signature will produce the signature.
//
// measurementIsAllowed decides whether the software the machine launched is
// software this owner accepts. It is passed in rather than decided here: which
// measurements are acceptable is a policy question about who publishes and
// approves them, and the answer belongs with whoever holds that list, not
// buried in a verification routine.
func CheckBoxOfferBeforeSigning(offer BoxOffer, measurementIsAllowed func(measurement []byte) bool) error {
	if offer.InceptionEvent == nil {
		return fmt.Errorf("%w: there is no event to sign", ErrOfferUnverified)
	}
	if len(offer.Report) == 0 {
		return fmt.Errorf("%w: the machine produced no attestation, so nothing says it is sealed at all",
			ErrOfferUnverified)
	}

	// What the identifier commits to. Read from the event rather than taken
	// alongside it, so the keys being checked are the keys the identifier
	// vouches for and there is no gap between the two where a different set
	// could be substituted.
	expected, err := iacrypto.BoxKeyBindingForEvent(offer.InceptionEvent)
	if err != nil {
		if errors.Is(err, iacrypto.ErrNotAnchored) {
			return fmt.Errorf("%w: this identifier does not commit to any encryption keys, so "+
				"signing it would vouch for keys that could be changed afterwards", ErrOfferUnverified)
		}
		return fmt.Errorf("%w: %v", ErrOfferUnverified, err)
	}

	report, err := secureenclave.ParseSNPReport(offer.Report)
	if err != nil {
		return fmt.Errorf("%w: the attestation could not be read: %v", ErrOfferUnverified, err)
	}

	if measurementIsAllowed == nil {
		return fmt.Errorf("%w: no policy was supplied for which software is acceptable, and "+
			"defaulting to 'any' would accept a machine running anything", ErrOfferUnverified)
	}
	if !measurementIsAllowed(report.Measurement) {
		return fmt.Errorf("%w: this machine launched software this owner has not accepted",
			ErrOfferUnverified)
	}

	// The hardware statement must be about THESE keys. Without this the report
	// proves only that some sealed machine exists somewhere, which is true and
	// useless — it is the step that ties the attestation to the identity rather
	// than leaving two unrelated proofs side by side.
	if !bytes.Equal(report.ReportData, secureenclave.BindReportData(expected)) {
		return fmt.Errorf("%w: the hardware vouches for different keys than the ones this "+
			"identifier commits to", ErrOfferUnverified)
	}

	if report.Unsigned() {
		return fmt.Errorf("%w: nothing signed this attestation, so it is a statement with no "+
			"author rather than one from the hardware", ErrOfferUnverified)
	}
	if report.DebugAllowed() {
		return fmt.Errorf("%w: this machine was started in a state where its memory can be "+
			"inspected, so nothing it holds is private", ErrOfferUnverified)
	}
	return nil
}
