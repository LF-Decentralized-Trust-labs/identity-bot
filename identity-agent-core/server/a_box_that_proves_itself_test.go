package server

import (
	"encoding/base64"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/secureenclave"
)

// The attestation a stand-in box offers, and what makes it acceptable.
//
// Before this existed, the handler tests sent allow_unattested and their fake
// boxes proved nothing — so every test about WHO owns a machine, or which
// identity may claim it, ran down a path production no longer has. Removing the
// flag is what forced them onto the real one, and this is the smallest way to
// put them there: a report bound to the keys the box offered, a measurement the
// owner accepts, and a chain verifier standing in for AMD.
//
// It substitutes the verifier, never the requirement. A test that wants a box
// adopted has to hand over a report, exactly as a real box does.
const stubBoxMeasurement = 0x11

func aBoxThatProvesItself(t *testing.T, publicKey, nextPublicKey, backupSigningKey string) string {
	t.Helper()
	bound, err := iacrypto.PairingOfferBinding(publicKey, nextPublicKey, backupSigningKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(syntheticReport(bound, stubBoxMeasurement))
}

// acceptsThatBox configures an Identity Agent to adopt what aBoxThatProvesItself offers:
// the measurement is accepted, and the chain check stands in for AMD.
func acceptsThatBox(s *CoreServer) {
	measurement := make([]byte, secureenclave.MeasurementSize)
	for i := range measurement {
		measurement[i] = stubBoxMeasurement
	}
	s.AcceptedMeasurements = [][]byte{measurement}
	s.snpChainVerifier = func([]byte) error { return nil }
}

// aMachineThatCanAttest makes a real Identity Agent under test offer a report, the way a
// sealed one does. For the tests that pair with an actual CoreServer rather
// than a stand-in HTTP server.
//
// Restored on cleanup, because it is process-wide and a test that left it set
// would silently give every later test hardware it does not have.
func aMachineThatCanAttest(t *testing.T) {
	t.Helper()
	prev := snpReportForOffer
	snpReportForOffer = func(binding string) (*secureenclave.SNPReport, error) {
		return &secureenclave.SNPReport{Raw: syntheticReport(binding, stubBoxMeasurement)}, nil
	}
	t.Cleanup(func() { snpReportForOffer = prev })
}
