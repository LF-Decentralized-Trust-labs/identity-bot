package server

import (
	"testing"

	"identity-agent-core/drivers"
)

// A credential this agent recorded as revoked stays revoked when the log kept
// for it holds only its issuance and is supplied for the proof of issuance: a
// partial log is never evidence that a credential is in force.
func TestAPartialKeptLogDoesNotUndoARevocationThisAgentRecorded(t *testing.T) {
	s, said, acdc, _ := issuedThenRevoked(t)
	rec, err := s.DataStore.GetCredential(said)
	if err != nil || rec == nil {
		t.Fatalf("no record: %v", err)
	}
	rec.Status = "revoked"
	if err := s.DataStore.SaveCredential(*rec); err != nil {
		t.Fatal(err)
	}
	cred, err := readCredentialHere(acdc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.verifyCredentialHere(&drivers.DriverVerifyCredentialRequest{
		AcdcJson:        acdc,
		IssuerKelEvents: s.issuerLogForVerification(cred.Issuer),
	}, cred, s.issuanceLogForVerification(cred, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got.RevocationStatus != revocationRevoked || got.Verified {
		t.Fatalf("a credential this agent recorded as revoked read %q, verified=%v", got.RevocationStatus, got.Verified)
	}
}
