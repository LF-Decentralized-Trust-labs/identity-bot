package secureenclave

import (
	"encoding/hex"
	"fmt"
)

// Which physical machine is this?
//
// Attestation answers "what am I" — genuine silicon, running this image, at
// this firmware level. It cannot answer "whose am I". The manufacturer's key
// service is open to anyone, so a machine an attacker owns produces reports
// that verify exactly as well as ours, and the vendor has said in writing that
// an attacker-owned machine is outside the threat model it defends.
//
// The gap is closed once, out of band, by a person: at enrolment, with physical
// assurance that this is the intended machine, we record the identifier of the
// hardware itself. Everything afterwards pins to that recorded value. Without
// it, every later attestation check is satisfied by any machine of the same
// make on earth — which is a 2008 result about TPMs (Parno's cuckoo attack)
// that has never been solved in-band, and will not be by us.
//
// So this file's whole job is to produce a durable identifier for the hardware,
// and to be honest when it cannot.

// MachineIDKind names where a machine identifier came from. The source matters
// as much as the value: they are not interchangeable and must never be compared
// across kinds.
type MachineIDKind string

const (
	// MachineIDSNPChip is CHIP_ID from an SEV-SNP attestation report — the
	// physical processor. Available only from INSIDE a sealed guest, because
	// only a guest can obtain a report. A host cannot produce one about itself.
	MachineIDSNPChip MachineIDKind = "snp-chip-id"

	// MachineIDTPMEndorsement is the hash of a TPM 2.0 endorsement key. This is
	// the identifier available to a HOST — a machine that runs guests rather
	// than being one. Not yet implemented; see tpmEndorsementID.
	MachineIDTPMEndorsement MachineIDKind = "tpm-ek"

	// MachineIDNone means no hardware identifier is obtainable here.
	MachineIDNone MachineIDKind = ""
)

// MachineIdentity is a hardware identifier and where it came from.
type MachineIdentity struct {
	Kind MachineIDKind `json:"kind"`
	// Value is lowercase hex. Empty when Kind is MachineIDNone.
	Value string `json:"value,omitempty"`
	// Why explains an absent or partial answer in terms an operator can act on.
	Why string `json:"why,omitempty"`
}

// Known reports whether this identifies a specific machine.
func (m MachineIdentity) Known() bool { return m.Kind != MachineIDNone && m.Value != "" }

// Matches reports whether m is the same machine as other. Kind and value must
// both agree: a TPM endorsement hash and an SNP chip id are different
// namespaces, and a value that happened to collide across them would mean
// nothing.
func (m MachineIdentity) Matches(other MachineIdentity) bool {
	return m.Known() && other.Known() && m.Kind == other.Kind && m.Value == other.Value
}

func (m MachineIdentity) String() string {
	if !m.Known() {
		if m.Why != "" {
			return "unidentified machine (" + m.Why + ")"
		}
		return "unidentified machine"
	}
	return string(m.Kind) + ":" + m.Value
}

// IdentifyMachine returns the best hardware identifier available in this
// process, or an explained absence.
//
// It never invents one. A caller deciding whether to trust a machine must be
// able to tell "this is machine X" from "I could not tell", and a synthesised
// placeholder would collapse that distinction at exactly the moment it matters.
func IdentifyMachine() MachineIdentity {
	// A sealed guest can prove which processor it is running on. Bind the report
	// to a fixed label rather than to a caller value: we are asking about the
	// hardware here, not attesting anything to anybody.
	if SNPAvailable() {
		rep, err := GetSNPReport("machine-identity")
		if err != nil {
			return MachineIdentity{Why: fmt.Sprintf("SEV-SNP guest device is present but "+
				"would not produce a report: %v", err)}
		}
		parsed, err := ParseSNPReport(rep.Raw)
		if err != nil {
			return MachineIdentity{Why: fmt.Sprintf("SEV-SNP produced a report that cannot "+
				"identify a machine: %v", err)}
		}
		return MachineIdentity{Kind: MachineIDSNPChip, Value: parsed.ChipIDHex()}
	}

	// Otherwise this is a host, or an ordinary machine. Its hardware identity
	// comes from a TPM.
	if id, why := tpmEndorsementID(); id != "" {
		return MachineIdentity{Kind: MachineIDTPMEndorsement, Value: id}
	} else if why != "" {
		return MachineIdentity{Why: why}
	}

	return MachineIdentity{Why: "no SEV-SNP guest device and no usable TPM 2.0"}
}

// MachineIdentityFromSNPReport reads the hardware identity out of a report
// somebody else obtained — the enrolment case, where the report is produced on
// the machine being enrolled and evaluated here.
func MachineIdentityFromSNPReport(raw []byte) (MachineIdentity, error) {
	parsed, err := ParseSNPReport(raw)
	if err != nil {
		return MachineIdentity{}, err
	}
	return MachineIdentity{Kind: MachineIDSNPChip, Value: parsed.ChipIDHex()}, nil
}

// ParseMachineIdentity reads back the recorded form, rejecting anything it
// cannot make sense of rather than returning a partially-populated identity
// that would compare unequal to everything and be read as "different machine"
// instead of "corrupt record".
func ParseMachineIdentity(kind, value string) (MachineIdentity, error) {
	k := MachineIDKind(kind)
	switch k {
	case MachineIDSNPChip, MachineIDTPMEndorsement:
	default:
		return MachineIdentity{}, fmt.Errorf("unknown machine identifier kind %q", kind)
	}
	if value == "" {
		return MachineIdentity{}, fmt.Errorf("machine identifier of kind %q has no value", kind)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return MachineIdentity{}, fmt.Errorf("machine identifier %q is not hex: %w", value, err)
	}
	return MachineIdentity{Kind: k, Value: value}, nil
}
