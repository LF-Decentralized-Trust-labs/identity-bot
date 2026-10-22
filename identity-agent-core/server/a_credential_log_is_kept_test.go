package server

import (
	"encoding/base64"
	"testing"

	"identity-agent-core/keriengine"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// A grant's transaction log, issuance and revocation, is still there to hand a
// verifier after the process restarts: the engine that made it forgets it, the
// stored log does not, and keri-go says it ends in "revoked".
func TestARevocationCanStillBeProvedAfterARestart(t *testing.T) {
	s, agent := grantWorld(t)
	grantSAID, err := s.issueCapabilityGrant(agent)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := s.DataStore.GetCredential(grantSAID)
	if rec == nil || rec.RegistrySAID == "" {
		t.Fatalf("the grant was not issued into a registry: %+v", rec)
	}
	if events, status, err := s.credentialLog(rec.RegistrySAID, grantSAID); err != nil || status != keri.StatusIssued || len(events) != 1 {
		t.Fatalf("after issue: %d events, %q, %v", len(events), status, err)
	}
	if _, err := s.revokeIssuedCredential(rec); err != nil {
		t.Fatal(err)
	}

	// The restart: a new engine knows nothing, and the store is reopened from disk.
	s.KeriDriver = keriengine.New()
	reopened, err := store.NewSQLiteStore(s.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	s.DataStore = reopened

	events, status, err := s.credentialLog(rec.RegistrySAID, grantSAID)
	if err != nil {
		t.Fatalf("the log could not be read back after a restart: %v", err)
	}
	if status != keri.StatusRevoked || len(events) != 2 {
		t.Fatalf("after a restart the log shows %d events ending %q; want the issuance and its revocation", len(events), status)
	}

	// The registry's own inception is kept as published too, so the registry
	// the log names can be checked as well.
	reg, err := s.DataStore.GetRegistry(rec.RegistrySAID)
	if err != nil || reg == nil || reg.VcpRawB64 == "" {
		t.Fatalf("the registry's inception was not kept as published: %+v %v", reg, err)
	}
	vcp, _ := base64.StdEncoding.DecodeString(reg.VcpRawB64)
	ev, err := keri.VerifyTELEvent(vcp)
	if err != nil || ev.Subject != rec.RegistrySAID {
		t.Fatalf("the kept registry inception does not verify as %s: %+v %v", rec.RegistrySAID, ev, err)
	}
}

// A credential with no kept log is never reported as in force.
func TestACredentialWithNoKeptLogIsNotCalledValid(t *testing.T) {
	s, agent := grantWorld(t)
	grantSAID, err := s.issueCapabilityGrant(agent)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := s.DataStore.GetCredential(grantSAID)
	if _, status, err := s.credentialLog(rec.RegistrySAID, "Enever-issued-here"); err == nil || status != "" {
		t.Fatalf("an unknown credential was given a status: %q %v", status, err)
	}
}

// An event that is not the credential's, or does not verify, is not kept as
// proof of it.
func TestOnlyTheCredentialsOwnEventsAreKept(t *testing.T) {
	s, agent := grantWorld(t)
	first, err := s.issueCapabilityGrant(agent)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := s.DataStore.GetCredential(first)
	kept, _ := s.DataStore.GetCredentialTEL(rec.RegistrySAID, first)
	if len(kept) != 1 {
		t.Fatalf("issuance not kept: %d", len(kept))
	}
	// A genuine issuance of another credential, never kept before, so only the
	// check of what it is about can refuse it.
	other := rec.SchemaSAID
	iss, err := keri.BuildIssuance(keri.IssuanceInput{CredentialSAID: other, Registry: rec.RegistrySAID,
		DT: "2026-10-22T00:00:00.000000+00:00"})
	if err != nil {
		t.Fatal(err)
	}
	issB64 := base64.StdEncoding.EncodeToString(iss)
	if err := s.keepCredentialEvent(rec.RegistrySAID, agent.PairwiseAID, issB64); err == nil {
		t.Fatal("another credential's issuance was kept as this one's")
	}
	if err := s.keepCredentialEvent(agent.DelegatorAID, other, issB64); err == nil {
		t.Fatal("an issuance into one registry was kept as one into another")
	}
	raw, _ := base64.StdEncoding.DecodeString(kept[0].RawB64)
	raw[len(raw)-3] ^= 1
	if err := s.keepCredentialEvent(rec.RegistrySAID, first, base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("an altered issuance was kept")
	}
}
