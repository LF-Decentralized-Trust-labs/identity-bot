package secureenclave

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"testing"
)

// A development report round-trips: it parses as a real SNP report, reads back
// the measurement and binding it was built with, announces itself as debug, and
// verifies against the development attestation key.
func TestDevSNPReportRoundTrips(t *testing.T) {
	measurement := bytes.Repeat([]byte{0xAB}, MeasurementSize)
	const value = "pairing-aid-under-test"

	report, err := GenerateDevSNPReport(value, measurement)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	parsed, err := ParseSNPReport(report)
	if err != nil {
		t.Fatalf("a development report must parse as a real SNP report: %v", err)
	}
	if !bytes.Equal(parsed.Measurement, measurement) {
		t.Fatalf("measurement did not round-trip")
	}
	if !bytes.Equal(parsed.ReportData, BindReportData(value)) {
		t.Fatalf("the binding did not round-trip")
	}
	if !parsed.DebugAllowed() {
		t.Fatal("a development report must carry the debug bit, so production refuses it on sight")
	}
	if parsed.Unsigned() {
		t.Fatal("a development report must read as signed, or ParseSNPReport rejects it")
	}
	if err := VerifyDevSNPReport(report); err != nil {
		t.Fatalf("the development verifier must accept a report the development key signed: %v", err)
	}
}

// Production refuses a development report two independent ways: the debug bit
// (checked before any signature) and the signature itself, which is not AMD's.
// This pins the debug-bit half; the chain half is that VerifyDevSNPReport is the
// ONLY verifier that holds the development key, and the production AMD verifier
// never does.
func TestProductionRefusesADevReportOnTheDebugBit(t *testing.T) {
	report, err := GenerateDevSNPReport("x-challenge-value", bytes.Repeat([]byte{1}, MeasurementSize))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSNPReport(report)
	if err != nil {
		t.Fatal(err)
	}
	// A production build is not dev, so the shared refusal rejects the report.
	if !DebugReportRefused(parsed.DebugAllowed(), false) {
		t.Fatal("a production build must refuse a development report for its debug bit")
	}
	// A development build is allowed to look past the debug bit.
	if DebugReportRefused(parsed.DebugAllowed(), true) {
		t.Fatal("a development build must not refuse a development report on the debug bit")
	}
}

// Tampering with the signed body after signing invalidates it: the development
// verifier is checking the signature, not merely the presence of one.
func TestDevVerifierRejectsATamperedReport(t *testing.T) {
	report, err := GenerateDevSNPReport("value-16-chars-min", bytes.Repeat([]byte{2}, MeasurementSize))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDevSNPReport(report); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	report[offMeasurement] ^= 0xFF // flip a bit inside the signed region
	if err := VerifyDevSNPReport(report); err == nil {
		t.Fatal("a report whose signed body was altered must not verify")
	}
}

// A report signed by any key other than the development attestation key is
// refused — so the development verifier is a real trust decision, not "accept
// anything that is shaped like a report."
func TestDevVerifierRejectsAForeignKey(t *testing.T) {
	report, err := GenerateDevSNPReport("value-16-chars-min", bytes.Repeat([]byte{3}, MeasurementSize))
	if err != nil {
		t.Fatal(err)
	}
	// Re-sign the same body with a different P-384 key and write that signature in.
	foreign, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384(report[:reportSignedLength])
	r, s, err := ecdsa.Sign(rand.Reader, foreign, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	for i := range report[reportSignatureOffset:] {
		report[reportSignatureOffset+i] = 0
	}
	putReportComponentLE(report[reportSignatureOffset:reportSignatureOffset+ecdsaComponentLength], r)
	putReportComponentLE(report[reportSignatureOffset+ecdsaComponentLength:reportSignatureOffset+2*ecdsaComponentLength], s)

	if err := VerifyDevSNPReport(report); err == nil {
		t.Fatal("a report signed by a foreign key must not verify against the development key")
	}
}

// The development key is deterministic: derived twice, it is the same key.
func TestDevAttestationKeyIsDeterministic(t *testing.T) {
	a, b := devAttestationKey(), devAttestationKey()
	if a.D.Cmp(b.D) != 0 || a.X.Cmp(b.X) != 0 || a.Y.Cmp(b.Y) != 0 {
		t.Fatal("the development attestation key must be identical every time it is derived")
	}
}
