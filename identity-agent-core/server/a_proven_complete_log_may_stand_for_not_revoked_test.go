package server

import (
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/keriengine"
)

// verifyOutsideHere checks an outside issuer's credential the way every path in
// this agent does, through verifyCredentialHere, and returns the log it asked
// the witnesses for with the reply.
func (w *registryWorld) verifyOutsideHere(iss *drivers.DriverIssueCredentialResponse, keepAsUnproven bool) (verifyReply, issuanceLog) {
	w.t.Helper()
	pointTheBootstrapPoolAt(w.t, w.bob.witnessKey, w.base)
	s := agentWithNoIdentity(w.t)
	s.KeriDriver = keriengine.New()
	cred, err := readCredentialHere(iss.AcdcJsonB64)
	if err != nil {
		w.t.Fatal(err)
	}
	log := s.issuanceLogForVerification(cred, w.kel)
	if keepAsUnproven {
		log.provenComplete = false // the same events, as a log kept here would be
	}
	reply, err := s.verifyCredentialHere(&drivers.DriverVerifyCredentialRequest{
		AcdcJson:        iss.AcdcJsonB64,
		IssuerKelEvents: log.issuerKel,
	}, cred, log)
	if err != nil {
		w.t.Fatal(err)
	}
	return reply, log
}

func TestAWitnessFetchedLogProvenCompleteStandsForNotRevoked(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	w.post(vcpB64(reg), iss.IssRawBytesB64)
	reply, log := w.verifyOutsideHere(iss, false)
	if !log.provenComplete {
		t.Fatal("a log fetched from the witnesses and checked against the key log was not proven complete")
	}
	if reply.RevocationStatus != revocationNotRevoked || !reply.Verified {
		t.Fatalf("an outside credential with a proven-complete live log read %q verified=%v %v", reply.RevocationStatus, reply.Verified, reply.Errors)
	}
}

func TestTheSameLogKeptHereNeverStandsForNotRevoked(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	w.post(vcpB64(reg), iss.IssRawBytesB64)
	reply, _ := w.verifyOutsideHere(iss, true)
	if reply.RevocationStatus == revocationNotRevoked {
		t.Fatalf("an unproven log, which may be partial, read as not revoked")
	}
	if reply.RevocationStatus != revocationNoRegistryState {
		t.Fatalf("status = %q, want %q", reply.RevocationStatus, revocationNoRegistryState)
	}
}

func TestAnUnprovenLogStillAddsARevocation(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	rev := w.revoke(reg.RegistrySaid, iss, true)
	w.post(vcpB64(reg), iss.IssRawBytesB64, rev.RevRawBytesB64)
	reply, _ := w.verifyOutsideHere(iss, true)
	if reply.RevocationStatus != revocationRevoked || reply.Verified {
		t.Fatalf("a revocation in a kept log read %q verified=%v", reply.RevocationStatus, reply.Verified)
	}
}

func TestAWitnessLogThatLeavesOutASealedRevocationIsNeitherNotRevokedNorVerified(t *testing.T) {
	w := newRegistryWorld(t)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	w.revoke(reg.RegistrySaid, iss, true) // sealed in the key log, event never given
	w.post(vcpB64(reg), iss.IssRawBytesB64)
	reply, log := w.verifyOutsideHere(iss, false)
	if log.provenComplete {
		t.Fatal("a log missing a sealed revocation was proven complete")
	}
	if reply.RevocationStatus == revocationNotRevoked || reply.Verified {
		t.Fatalf("a log omitting a sealed revocation read %q verified=%v", reply.RevocationStatus, reply.Verified)
	}
}

func TestThisAgentsOwnRecordWinsOverAProvenCompleteLog(t *testing.T) {
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
	}, cred, issuanceLog{events: []string{"x"}, provenComplete: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.RevocationStatus != revocationRevoked || got.Verified {
		t.Fatalf("a proven-complete log overrode this agent's record: %q verified=%v", got.RevocationStatus, got.Verified)
	}
}
