package secureenclave

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Reading an SEV-SNP attestation report.
//
// The report arrives as 1184 opaque bytes. Verifying its signature and
// certificate chain is a separate job with its own dependencies; this file only
// reads the fields out, and it does the cheap structural checks that need no
// network and no AMD root — the ones whose absence would otherwise let obviously
// useless bytes travel a long way before anybody noticed.
//
// Field offsets below were taken from the report parser in
// github.com/google/go-sev-guest (abi/abi.go) rather than from AMD's published
// tables, which were not directly retrievable. A wrong offset here yields
// plausible-looking garbage rather than an error, so they are written as
// explicit named constants and asserted against a fixture in the tests.

// Report field offsets, ABI 1.x.
const (
	offPolicy       = 0x08  // uint64, little-endian
	offPlatformInfo = 0x40  // uint64
	offSignerInfo   = 0x48  // uint32
	offReportData   = 0x50  // 64 bytes
	offMeasurement  = 0x90  // 48 bytes
	offHostData     = 0xC0  // 32 bytes
	offReportedTCB  = 0x180 // uint64
	offChipID       = 0x1A0 // 64 bytes
	offSignature    = 0x2A0 // to the end of the report
)

// MeasurementSize is the launch measurement's length.
const MeasurementSize = 48

// ChipIDSize is the length of CHIP_ID — the identifier of the physical
// processor the guest is running on.
const ChipIDSize = 64

// policyDebugBit is POLICY bit 19. When set, the hypervisor may read guest
// memory — and the guest still produces a fully valid, chain-verifiable report.
// Nothing about the signature or the certificate chain catches this; only
// looking at the bit does.
const policyDebugBit = 1 << 19

// signerNone is SIGNER_INFO.SigningKey == 7 (`NoneReportSigner`): the report is
// not signed at all. Reachable from the host via SNP_SET_CONFIG.
const signerNone = 7

// ParsedReport is the fields of an attestation report that a caller acts on.
type ParsedReport struct {
	// Raw is the report as the hardware produced it. Signature verification runs
	// against these bytes; everything else here is a convenience read.
	Raw []byte

	// ChipID identifies the physical processor. This is the field that answers
	// "which machine", and it is the whole reason the enrolment ceremony exists:
	// a report proves a genuine AMD part ran a given image, never that the part
	// is ours. Recording this value at a moment of physical assurance is what
	// converts "some EPYC" into "our EPYC".
	ChipID []byte

	// Measurement is the launch measurement of the image that was started.
	Measurement []byte

	// ReportData is the 64 caller-supplied bytes the hardware signed alongside
	// the measurement — for us, a binding to the AID being enrolled.
	ReportData []byte

	// HostData is supplied by the HYPERVISOR, not the guest. Attested as
	// supplied, never attested as true. Read it if you like; do not trust it.
	HostData []byte

	Policy       uint64
	PlatformInfo uint64
	ReportedTCB  uint64
	SignerInfo   uint32
}

// DebugAllowed reports whether POLICY permits the hypervisor to read guest
// memory. A report with this set is cryptographically perfect and worth nothing.
func (p *ParsedReport) DebugAllowed() bool { return p.Policy&policyDebugBit != 0 }

// Unsigned reports whether SIGNER_INFO says no key signed this report.
func (p *ParsedReport) Unsigned() bool { return (p.SignerInfo>>2)&7 == signerNone }

// ChipIDHex is CHIP_ID as a lowercase hex string, the form it is recorded and
// compared in.
func (p *ParsedReport) ChipIDHex() string { return hex.EncodeToString(p.ChipID) }

// MeasurementHex is the launch measurement as lowercase hex.
func (p *ParsedReport) MeasurementHex() string { return hex.EncodeToString(p.Measurement) }

// ParseSNPReport reads a report and rejects the ones that cannot mean anything.
//
// What it refuses, and why each one matters:
//
//   - Wrong length. Nothing else can be trusted if the framing is wrong.
//   - An all-zero report. The kernel's response header carries a STATUS field;
//     a caller that ignores it and copies the payload anyway gets 1184 zero
//     bytes that look exactly like a report. This is the last place to catch it.
//   - An all-zero CHIP_ID. The host can set mask_chip_id, which zeroes the field
//     entirely. A zeroed chip ID cannot identify a machine, and treating it as
//     one would silently pin an allowlist to "any masked host".
//   - An unsigned report. If SIGNER_INFO says nothing signed this, there is no
//     point carrying it further.
//
// It does NOT verify the signature or the certificate chain. Those need AMD's
// roots and are deliberately a separate step; a caller must not read a
// successful parse as a verified report.
func ParseSNPReport(raw []byte) (*ParsedReport, error) {
	if len(raw) != ReportSize {
		return nil, fmt.Errorf("attestation report is %d bytes, want %d", len(raw), ReportSize)
	}
	if allZero(raw) {
		return nil, fmt.Errorf("attestation report is entirely zero — the firmware call did not " +
			"produce a report, and its status was not checked")
	}

	p := &ParsedReport{
		Raw:          bytes.Clone(raw),
		ChipID:       bytes.Clone(raw[offChipID : offChipID+ChipIDSize]),
		Measurement:  bytes.Clone(raw[offMeasurement : offMeasurement+MeasurementSize]),
		ReportData:   bytes.Clone(raw[offReportData : offReportData+ReportDataSize]),
		HostData:     bytes.Clone(raw[offHostData : offHostData+32]),
		Policy:       binary.LittleEndian.Uint64(raw[offPolicy : offPolicy+8]),
		PlatformInfo: binary.LittleEndian.Uint64(raw[offPlatformInfo : offPlatformInfo+8]),
		ReportedTCB:  binary.LittleEndian.Uint64(raw[offReportedTCB : offReportedTCB+8]),
		SignerInfo:   binary.LittleEndian.Uint32(raw[offSignerInfo : offSignerInfo+4]),
	}

	if allZero(p.ChipID) {
		return nil, fmt.Errorf("attestation report has an all-zero CHIP_ID — the host has masked " +
			"the chip identifier, so this report cannot identify a machine")
	}
	if p.Unsigned() {
		return nil, fmt.Errorf("attestation report declares itself unsigned (SIGNER_INFO signing key 7)")
	}
	if allZero(raw[offSignature:]) {
		return nil, fmt.Errorf("attestation report carries no signature")
	}
	return p, nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
