package secureenclave

import (
	"github.com/zeebo/blake3"
)

// AMD SEV-SNP guest attestation.
//
// An agent running in a sealed micro-VM can prove what it is. The hardware
// signs a report covering the measurement of the image that was launched, and
// a caller checks that measurement against the image they expect. That is the
// difference between infrastructure that promises not to look and infrastructure
// where looking is not available to it — but only if somebody actually asks for
// the report and checks it. Producing it is this file's job.
//
// The report is generated inside the guest. Nothing on the host can make one,
// which is exactly why it is worth anything: a provider cannot forge a claim
// about a VM it does not control the inside of.

// ReportSize is the length of an SEV-SNP attestation report (ABI 1.x).
const ReportSize = 1184

// ReportDataSize is the caller-supplied blob the hardware signs alongside the
// measurement.
const ReportDataSize = 64

// SNPReport is a raw attestation report and how to interpret it.
type SNPReport struct {
	// Raw is the signed report exactly as the hardware produced it. Verification
	// happens against these bytes; anything parsed out is a convenience.
	Raw []byte
	// ReportData is the 64 bytes bound into the report by the caller.
	ReportData []byte
}

// BindReportData turns a value the report should be bound to into the 64-byte
// REPORT_DATA field.
//
// Binding is what stops a report being lifted from one instance and presented
// by another. A report that merely says "some SNP guest ran the right image" is
// satisfied by any instance anywhere, including the provider's own. A report
// bound to the pairing AID says "the guest that minted THIS AID ran the right
// image", which is the claim a person pairing actually needs.
func BindReportData(value string) []byte {
	sum := blake3.Sum256([]byte("IA-SNP-BIND-V1\n" + value))
	out := make([]byte, ReportDataSize)
	copy(out, sum[:])
	return out
}

// SNPAvailable reports whether this process can obtain an attestation report —
// that is, whether it is running inside an SEV-SNP guest with the guest device
// present.
func SNPAvailable() bool { return snpAvailable() }

// GetSNPReport asks the hardware for a report bound to value.
//
// It returns an error rather than an empty report when unavailable: "I am not
// in a sealed VM" and "I am, and here is the proof" must never be confusable,
// because the whole point of asking is to tell them apart.
func GetSNPReport(value string) (*SNPReport, error) {
	data := BindReportData(value)
	raw, err := getSNPReport(data)
	if err != nil {
		return nil, err
	}
	return &SNPReport{Raw: raw, ReportData: data}, nil
}
