package server

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"os"
	"time"

	"identity-agent-core/volume"
)

// Everything this agent's trust rests on, in one answer.
//
// The facts are already here — a report from the processor, what the platform
// says about hardware key protection, what this identity was delegated. They
// are in three places answering three questions, which is right for the code
// and wrong for the person who wants to know whether their agent is sound.
// This assembles them so a screen can ask once.
//
// Owner-only, unlike /api/attestation next door. That one is public because a
// counterparty must be able to check a machine without being let inside it.
// This one adds what the owner knows and a stranger should not: whether the
// disk carries a recovery slot, what this device calls itself, what it is
// delegated to do.

// ProofState is what is known about one fact — and the middle value is the
// reason there are three.
//
// A machine that PROVED it has no hardware key protection and a machine nobody
// could ask are different facts, and the difference decides what somebody
// should do. The first is settled: there is no protection here. The second is
// an absence of information, and reporting it as absence would tell somebody
// their machine is inadequate on the strength of nobody having looked. The
// capability detector already refuses to do that; this preserves it as far as
// the screen.
type ProofState string

const (
	ProofVerified ProofState = "verified"
	ProofUnknown  ProofState = "unknown"
	ProofAbsent   ProofState = "absent"
)

// AttestationLineage is what an agent can say about its own foundations.
type AttestationLineage struct {
	// DeviceName is what this machine is called. Never an identifier — nobody
	// recognises their own machine by its AID.
	DeviceName string `json:"device_name"`

	// SealedHardware says whether this is the kind of machine that can prove
	// itself to a stranger at all. A personal computer cannot, and that is not
	// a shortcoming to report: there is nobody it needs to prove itself to.
	SealedHardware bool `json:"sealed_hardware"`

	ChipVendor string `json:"chip_vendor,omitempty"`
	ChipID     string `json:"chip_id,omitempty"`

	// ChainVerified is whether this agent checked the report back to the
	// manufacturer's root ITSELF. An operator's verification of its own
	// hardware is not evidence for anybody else, so only a check made here
	// counts here.
	ChainVerified           ProofState `json:"chain_verified"`
	ReportSignatureVerified ProofState `json:"report_signature_verified"`

	Measurement string `json:"measurement,omitempty"`

	// BuildName is what the software is CALLED. Without it the measurement is
	// ninety-six characters of hex and the row means nothing to anyone who did
	// not write it.
	BuildName                  string     `json:"build_name,omitempty"`
	MeasurementMatchesExpected ProofState `json:"measurement_matches_expected"`

	DebugDisabled        ProofState `json:"debug_disabled"`
	DiskEncrypted        ProofState `json:"disk_encrypted"`
	OwnerRecoveryPresent ProofState `json:"owner_recovery_present"`

	HardwareKeyProtection ProofState `json:"hardware_key_protection"`
	HardwareKeyName       string     `json:"hardware_key_name,omitempty"`

	DelegatedAID string `json:"delegated_aid,omitempty"`
	OwnerAID     string `json:"owner_aid,omitempty"`

	CheckedAt string `json:"checked_at"`
}

// handleAttestationLineage answers what this agent's trust rests on.
func (s *CoreServer) handleAttestationLineage(w http.ResponseWriter, r *http.Request) {
	out := AttestationLineage{
		DeviceName: s.deviceDisplayName(),
		CheckedAt:  time.Now().UTC().Format(time.RFC3339),

		// Unknown until something establishes otherwise. Every field here
		// starts at "nobody has checked", so a fact that fails to be gathered
		// is reported as unchecked rather than as absent.
		ChainVerified:              ProofUnknown,
		ReportSignatureVerified:    ProofUnknown,
		MeasurementMatchesExpected: ProofUnknown,
		DebugDisabled:              ProofUnknown,
		DiskEncrypted:              ProofUnknown,
		OwnerRecoveryPresent:       ProofUnknown,
		HardwareKeyProtection:      ProofUnknown,
	}

	// What the platform can say about holding a key in hardware. This is the
	// one link every machine can answer, sealed or not.
	if info := s.enclaveStatus(); info != nil {
		out.HardwareKeyName = info.BackingLabel
		switch {
		case info.HardwareBacked:
			out.HardwareKeyProtection = ProofVerified
		case info.TpmPresent != nil && !*info.TpmPresent:
			// Proven absent: the machine was asked and answered no.
			out.HardwareKeyProtection = ProofAbsent
		default:
			out.HardwareKeyProtection = ProofUnknown
		}
	}

	// Its own attestation, where it has one.
	if att := s.cachedAttestation(); att != nil {
		out.SealedHardware = true
		out.ChipVendor = "AMD"
		out.ChipID = att.ChipID
		out.Measurement = att.Measurement
		out.BuildName = s.buildDisplayName()

		if att.DebugAllowed {
			out.DebugDisabled = ProofAbsent
		} else {
			out.DebugDisabled = ProofVerified
		}

		// Whether the software it started is software this owner accepts. An
		// empty policy stays unknown rather than becoming a pass — the same
		// refusal the adoption gate makes.
		if raw, err := hex.DecodeString(att.Measurement); err == nil && len(raw) > 0 {
			if len(s.AcceptedMeasurements) == 0 {
				out.MeasurementMatchesExpected = ProofUnknown
			} else if s.acceptableMeasurement(raw) {
				out.MeasurementMatchesExpected = ProofVerified
			} else {
				out.MeasurementMatchesExpected = ProofAbsent
			}
		}

		// The chain, checked here rather than taken from the host. Reported
		// unknown when the manufacturer could not be reached, because an
		// outage is not evidence of a forgery.
		if reportRaw, err := decodeAttestationReport(att.Report); err == nil {
			if err := s.verifySNPChain(reportRaw); err == nil {
				out.ChainVerified = ProofVerified
				out.ReportSignatureVerified = ProofVerified
			} else {
				out.ChainVerified = ProofUnknown
				out.ReportSignatureVerified = ProofUnknown
			}
		}

		// The disk, which only this agent can answer about itself.
		enc, recov := s.volumeProtectionState()
		out.DiskEncrypted = enc
		out.OwnerRecoveryPresent = recov
	}

	if id, err := s.DataStore.GetIdentity(); err == nil && id != nil {
		out.DelegatedAID = id.AID
	}
	if owner, err := s.sealedOwnerAID(); err == nil {
		out.OwnerAID = owner
	}

	writeJSONResponse(w, out)
}

// enclaveStatus is what the platform can say about hardware key protection.
//
// The same detection the enclave endpoint serves, so the two never disagree
// about the machine they are both running on.
func (s *CoreServer) enclaveStatus() *EnclaveStatusResponse {
	got := detectEnclave()
	return &got
}

// deviceDisplayName is what to call this machine on screen.
//
// A name somebody chose, then what kind of thing it is. Never the identifier:
// nobody recognises their own machine by a 44-character string, and showing one
// where a name belongs is how a screen stops being for people.
func (s *CoreServer) deviceDisplayName() string {
	if n := os.Getenv("AGENT_DEVICE_NAME"); n != "" {
		return n
	}
	if s.cachedAttestation() != nil {
		return "This sealed computer"
	}
	return "This computer"
}

// buildDisplayName is what the software calls itself.
//
// Set by whoever assembles the image, because only they know whether this is
// the individual app or the organisation one and at what version. Without it a
// person is shown a measurement and no way to know what it is a measurement OF,
// which is the difference between a fact and a useful one.
func (s *CoreServer) buildDisplayName() string {
	if n := os.Getenv("AGENT_BUILD_NAME"); n != "" {
		return n
	}
	return "The software it started"
}

// decodeAttestationReport turns the published report back into bytes.
func decodeAttestationReport(b64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(b64)
}

// volumeProtectionState says whether this machine's data volume is encrypted
// and whether its owner has a way back into it.
//
// Only this agent can answer it — the facts live in a LUKS header on a device
// nobody outside the machine can read — and it is the pair of questions that
// decides whether an image update is an inconvenience or permanent data loss.
func (s *CoreServer) volumeProtectionState() (encrypted, ownerRecovery ProofState) {
	if s.cachedAttestation() == nil {
		return ProofUnknown, ProofUnknown
	}
	device := os.Getenv("AGENT_STATE_DEVICE")
	if device == "" {
		device = "/dev/vdb"
	}
	if _, err := os.Stat(device); err != nil {
		// No such volume on this machine. Not a failure to encrypt one — there
		// is nothing here to encrypt, which is a different statement.
		return ProofUnknown, ProofUnknown
	}
	has, err := volume.HasOwnerRecovery(device)
	if err != nil {
		// The volume exists and could not be read. Unknown rather than absent:
		// a lock we could not take says nothing about what is in the header.
		return ProofVerified, ProofUnknown
	}
	if has {
		return ProofVerified, ProofVerified
	}
	return ProofVerified, ProofAbsent
}

// sealedOwnerAID is who this agent belongs to, as sealed at adoption.
//
// Read from the sealed owner record rather than the identity, because an
// identity knows what it is and the owner is a separate fact established by a
// ceremony that may not have happened.
func (s *CoreServer) sealedOwnerAID() (string, error) {
	owner, err := s.ownerAuthority()
	if err != nil || owner == nil {
		return "", err
	}
	return owner.AID, nil
}
