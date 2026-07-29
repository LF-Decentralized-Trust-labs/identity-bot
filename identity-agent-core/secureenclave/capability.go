package secureenclave

// What this machine can actually protect a key with — and, just as important,
// what we genuinely do not know about it.
//
// The bug this exists to prevent is a specific one, and it was already in this
// package: a detector that answers "no hardware" when the truth is "we never
// looked." Three of the five platform signers here have an Available() that
// returns a hardcoded false — not detection that found nothing, but detection
// nobody wrote. On Windows that would be wrong for essentially every machine,
// since Windows 11 cannot ship without a TPM.
//
// It is not a mistake unique to us. Google's own go-attestation reads, in as
// many words: "If we fail to initialize the Platform Crypto Provider, we assume
// a TPM is not present." Anyone reaching for the obvious reference inherits it.
//
// So the contract here has one rule above all others:
//
//	ABSENT MUST BE PROVEN. UNKNOWN IS THE DEFAULT.
//
// A detector may only return Absent on positive evidence of absence. Every
// unrecognised error, every permission problem, every API that would not load
// resolves to Unknown. Unknown is not a failure state to be tidied away later —
// it is the honest answer, and it is what lets an agent say "we could not check
// this machine" instead of telling somebody their hardware is inadequate when
// it is not.

import "fmt"

// Status is what we were able to establish about hardware key protection.
type Status string

const (
	// Usable — proven, not inferred. A key was actually created in the hardware
	// and discarded, or an attestation report was actually obtained. Nothing
	// short of doing the thing counts.
	Usable Status = "usable"

	// Present — the hardware is there and answered, but cannot be used right
	// now: not provisioned, locked out, malfunctioning. Distinct from Absent
	// because the remedy is completely different, and distinct from Unknown
	// because we did learn something.
	Present Status = "present_unusable"

	// Absent — positively established that there is no hardware root. This is
	// the only status a detector may not guess at.
	Absent Status = "absent"

	// Unknown — we could not determine it. No permission, no API, an
	// unrecognised error, a platform we have not implemented. The default, and
	// never to be rendered to a person as "your device has no security
	// hardware."
	Unknown Status = "unknown"
)

// Kind names what is protecting the key, when something is.
type Kind string

const (
	KindNone         Kind = ""
	KindAppleEnclave Kind = "apple_secure_enclave"
	KindTPM2         Kind = "tpm2"
	KindStrongBox    Kind = "android_strongbox"
	KindAndroidTEE   Kind = "android_tee"
	KindSEVSNP       Kind = "amd_sev_snp"
	KindTDX          Kind = "intel_tdx"
	KindSoftwareOnly Kind = "software_only"
)

// Capability is one machine's answer.
type Capability struct {
	Status Status `json:"status"`
	Kind   Kind   `json:"kind,omitempty"`

	// Reason is a stable machine-readable slug — "tpm_absent_or_disabled_in_firmware",
	// "permission_denied", "not_implemented_on_this_build". Stable because it
	// will end up in support conversations and in whatever we ship to explain a
	// score ceiling, and a message that changes wording between releases cannot
	// be searched for.
	Reason string `json:"reason,omitempty"`

	// Detail carries the raw platform error, including numeric codes. Kept even
	// when it means nothing to us yet: the first release's job is to find out
	// which codes real machines actually produce, and a code we discarded is a
	// code we cannot learn from.
	Detail string `json:"detail,omitempty"`
}

// RootKeyPermitted reports whether an identity's ROOT key may live here.
//
// This is the question GS-12 turns on, and it is deliberately strict: only
// proven-usable hardware qualifies. Present-but-unusable does not, because a
// key cannot be protected by hardware that will not accept it. Unknown does
// not either — an unproven guess in the permissive direction puts somebody's
// identity in a file, which is the one failure that cannot be undone.
//
// Being refused here is not a refusal to use the software. Any device may run
// an agent as a delegated controller; this governs only where the root lives.
func (c Capability) RootKeyPermitted() bool {
	return c.Status == Usable
}

// NeedsHumanReview reports whether this machine is one we could not classify,
// and so is worth asking its owner about.
//
// Any capability table ships wrong about hardware that did not exist when it
// was written, and the failure is silent: a perfectly good machine gets told it
// is inadequate, its owner has no recourse, and we never hear. This is the
// signal that turns that into something we can learn from.
func (c Capability) NeedsHumanReview() bool {
	return c.Status == Unknown
}

// String is for logs and support, and says the uncertain thing out loud.
func (c Capability) String() string {
	switch c.Status {
	case Usable:
		return fmt.Sprintf("hardware key protection available (%s)", c.Kind)
	case Present:
		return fmt.Sprintf("hardware present but unusable (%s): %s", c.Kind, c.Reason)
	case Absent:
		return fmt.Sprintf("no hardware key protection: %s", c.Reason)
	default:
		return fmt.Sprintf("could not determine hardware key protection: %s", c.Reason)
	}
}

// Unproven builds an Unknown, which is what every detector returns when it
// cannot establish something. A helper rather than a literal because the
// tempting shortcut is to write Absent here, and a named constructor makes the
// right answer the easy one.
func Unproven(reason, detail string) Capability {
	return Capability{Status: Unknown, Reason: reason, Detail: detail}
}

// NotImplemented is the honest answer from a platform whose detector has not
// been written. It is Unknown rather than Absent for the reason this whole file
// exists: we have not looked, so we do not know.
func NotImplemented(platform string) Capability {
	return Capability{
		Status: Unknown,
		Reason: "not_implemented_on_this_build",
		Detail: "hardware detection is not implemented for " + platform +
			" — this says nothing about whether the machine has security hardware",
	}
}
