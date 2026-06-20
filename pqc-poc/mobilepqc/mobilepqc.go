// Package mobilepqc exports a gomobile-bindable PQC round-trip for C4 feasibility.
package mobilepqc

import "identity-bot/pqc-poc/roundtrip"

// RoundTrip runs ML-DSA-65 sign/verify and ML-KEM-768 encap/decap.
// Returns a status string for mobile smoke tests.
func RoundTrip() string {
	res, err := roundtrip.Run()
	if err != nil {
		return "FAIL: " + err.Error()
	}
	if !res.SigVerifyOK || !res.KemSecretOK {
		return "FAIL: " + res.String()
	}
	return "PASS: " + res.String()
}