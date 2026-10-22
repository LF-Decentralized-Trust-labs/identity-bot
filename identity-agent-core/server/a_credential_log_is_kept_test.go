package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

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

// refusingStore keeps nothing of one kind of credential event, as a full disk
// or a failing database would refuse it.
type refusingStore struct {
	store.Store
	kind string
}

func (r refusingStore) KeepCredentialEvent(ev store.CredentialTELEvent, anchor *store.EventRecord) error {
	if ev.Kind == r.kind {
		return errors.New("the database refused the write")
	}
	return r.Store.KeepCredentialEvent(ev, anchor)
}

// A revocation that cannot be kept is not made: the request fails, the
// credential stays as it was, and no anchor is kept for a revocation the log
// does not hold.
func TestARevocationThatCannotBeKeptIsNotMade(t *testing.T) {
	s, agent := grantWorld(t)
	grantSAID, err := s.issueCapabilityGrant(agent)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := s.DataStore.GetCredential(grantSAID)
	before, _ := s.DataStore.GetEvents(rec.IssuerAID)
	s.DataStore = refusingStore{Store: s.DataStore, kind: "rev"}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/credentials/"+grantSAID+"/revoke", nil)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("said", grantSAID)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
	s.handleRevokeCredential(w, r)

	if w.Code == http.StatusOK {
		t.Fatalf("a revocation that could not be kept was reported done: %s", w.Body.String())
	}
	after, _ := s.DataStore.GetCredential(grantSAID)
	if after.Status == "revoked" {
		t.Fatal("the credential was recorded as revoked with no kept revocation")
	}
	if events, _ := s.DataStore.GetEvents(rec.IssuerAID); len(events) != len(before) {
		t.Fatalf("the revocation's anchor was kept without the revocation: %d events, was %d", len(events), len(before))
	}
	if _, status, err := s.credentialLog(rec.RegistrySAID, grantSAID); err != nil || status != keri.StatusIssued {
		t.Fatalf("the log no longer reads as issued: %q %v", status, err)
	}
}

// A credential recorded here as revoked whose kept log ends in its issuance is
// not reported as issued.
func TestARevokedCredentialIsNeverReportedIssued(t *testing.T) {
	s, agent := grantWorld(t)
	grantSAID, err := s.issueCapabilityGrant(agent)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := s.DataStore.GetCredential(grantSAID)
	if err := s.DataStore.UpdateCredentialStatus(grantSAID, "revoked"); err != nil {
		t.Fatal(err)
	}
	if _, status, err := s.credentialLog(rec.RegistrySAID, grantSAID); err == nil {
		t.Fatalf("a revoked credential's log was reported as %q", status)
	}
}

// A revocation anchored in the issuer's key log but missing from the kept log,
// as a crash between the two used to leave it, makes the log unprovable rather
// than a shorter one that reads "issued".
func TestALogMissingAnAnchoredRevocationIsRefused(t *testing.T) {
	s, agent := grantWorld(t)
	grantSAID, err := s.issueCapabilityGrant(agent)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := s.DataStore.GetCredential(grantSAID)
	resp, err := s.KeriDriver.RevokeCredential(rec.IssuerAID, rec.SAID, rec.RegistrySAID, rec.IssSAID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.saveOwnInteraction(rec.IssuerAID, resp.IxnEvent, resp.IxnRawBytesB64, resp.SequenceNumber, ""); err != nil {
		t.Fatal(err)
	}
	if _, status, err := s.credentialLog(rec.RegistrySAID, grantSAID); err == nil {
		t.Fatalf("a log missing an anchored revocation was reported as %q", status)
	}
}

// A registry's inception is kept only if it verifies, is the registry named,
// and is anchored by the event kept with it; and a registry made before
// inceptions were kept is replaced for new credentials, while what was issued
// in it is reported as unprovable.
func TestARegistryIsKeptOnlyWithAProvableInception(t *testing.T) {
	s, agent := grantWorld(t)
	grantSAID, err := s.issueCapabilityGrant(agent)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := s.DataStore.GetCredential(grantSAID)
	reg, _ := s.DataStore.GetRegistry(rec.RegistrySAID)
	events, _ := s.DataStore.GetEvents(rec.IssuerAID)
	var anchor string
	for _, e := range events {
		if raw, _ := base64.StdEncoding.DecodeString(e.RawBytesB64); len(raw) > 0 {
			if ev, err := keri.ParseEvent(raw); err == nil {
				if seals, _ := ev.Seals(); len(seals) > 0 && seals[0].Identifier == reg.RegistrySAID {
					anchor = e.RawBytesB64
				}
			}
		}
	}
	if anchor == "" {
		t.Fatal("the registry's anchor was not kept")
	}
	if err := checkRegistryInception(reg.VcpRawB64, reg.RegistrySAID, anchor); err != nil {
		t.Fatalf("the kept inception does not check: %v", err)
	}
	if err := checkRegistryInception(reg.VcpRawB64, "Eanother-registry", anchor); err == nil {
		t.Fatal("an inception was accepted as another registry's")
	}
	raw, _ := base64.StdEncoding.DecodeString(reg.VcpRawB64)
	raw[len(raw)-3] ^= 1
	if err := checkRegistryInception(base64.StdEncoding.EncodeToString(raw), reg.RegistrySAID, anchor); err == nil {
		t.Fatal("an altered inception was accepted")
	}
	if err := checkRegistryInception(reg.VcpRawB64, reg.RegistrySAID, events[0].RawBytesB64); err == nil {
		t.Fatal("an inception was accepted with an anchor that does not anchor it")
	}

	// An issuance, anchored and genuine, is still not a registry's inception.
	kept, _ := s.DataStore.GetCredentialTEL(rec.RegistrySAID, grantSAID)
	var issAnchor string
	for _, e := range events {
		if raw, _ := base64.StdEncoding.DecodeString(e.RawBytesB64); len(raw) > 0 {
			if ev, err := keri.ParseEvent(raw); err == nil {
				if seals, _ := ev.Seals(); len(seals) > 0 && seals[0].Identifier == grantSAID {
					issAnchor = e.RawBytesB64
				}
			}
		}
	}
	if err := checkRegistryInception(kept[0].RawB64, grantSAID, issAnchor); err == nil {
		t.Fatal("a credential's issuance was accepted as a registry's inception")
	}
}

// blankInceptionStore answers as a database written before registry
// inceptions were kept.
type blankInceptionStore struct{ store.Store }

func (b blankInceptionStore) GetRegistry(said string) (*store.CredentialRegistry, error) {
	r, err := b.Store.GetRegistry(said)
	if r != nil {
		blank := *r
		blank.VcpRawB64 = ""
		return &blank, err
	}
	return r, err
}

// A registry made before inceptions were kept is not issued into again, and
// what was issued in it is reported as unprovable, never as in force.
func TestARegistryWithoutAKeptInceptionIsNotTrusted(t *testing.T) {
	s, agent := grantWorld(t)
	owner, _ := s.DataStore.GetIdentity()
	old := store.CredentialRegistry{RegistrySAID: "Eold-registry", IssuerAID: owner.AID, CreatedAt: "2026-01-01T00:00:00Z"}
	if err := s.DataStore.SaveRegistry(old); err != nil {
		t.Fatal(err)
	}
	grantSAID, err := s.issueCapabilityGrant(agent)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := s.DataStore.GetCredential(grantSAID)
	if rec.RegistrySAID == old.RegistrySAID {
		t.Fatal("a credential was issued into a registry whose inception cannot be proved")
	}
	s.DataStore = blankInceptionStore{s.DataStore}
	if _, status, err := s.credentialLog(rec.RegistrySAID, grantSAID); err == nil {
		t.Fatalf("a credential in a registry with no kept inception was reported as %q", status)
	}
}

// Two revocations of one credential at once make one revocation, and both
// callers are told it is revoked.
func TestTwoRevocationsAtOnceMakeOne(t *testing.T) {
	s, agent := grantWorld(t)
	grantSAID, err := s.issueCapabilityGrant(agent)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := s.DataStore.GetCredential(grantSAID)
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			copy := *rec
			if ok, err := s.revokeIssuedCredential(&copy); err != nil || !ok {
				errs <- fmt.Errorf("ok=%v err=%v", ok, err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("a concurrent revocation failed: %v", err)
	}
	events, status, err := s.credentialLog(rec.RegistrySAID, grantSAID)
	if err != nil || status != keri.StatusRevoked || len(events) != 2 {
		t.Fatalf("after concurrent revocations: %d events, %q, %v", len(events), status, err)
	}
}
