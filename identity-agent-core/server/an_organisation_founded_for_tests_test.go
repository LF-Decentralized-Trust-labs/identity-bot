package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/drivers"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/keriengine"
	"identity-agent-core/login"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// Fixtures for the core's own tests: an organisation founded as startup finds
// it, and one with a controller paired and granted. They hold no AI agent; the
// AI-agent tests build on them.

// foundOrganisation founds an organisation that holds its own key in s, naming
// witnesses when given: founded and reloaded into the engine the way startup
// reloads it, with its founding event signed and stored. It returns the
// organisation's identifier and the engine that holds its key.
func foundOrganisation(t *testing.T, s *CoreServer, witnesses []string, toad int) (string, *keriengine.Engine) {
	t.Helper()
	e := keriengine.New()
	s.KeriDriver = e
	s.engineSigns()

	owner, _ := s.DataStore.GetIdentity()
	seed, err := s.identitySigningSeed()
	if err != nil {
		t.Fatal(err)
	}
	next, _ := keri.GenerateSigner(true)
	nextPub, _ := next.PublicKey()
	founding := keriengine.New()
	root, err := founding.Incept(drivers.InceptionRequest{
		PublicKey: owner.PublicKey, NextPublicKey: nextPub, Name: "owner", Witnesses: witnesses, Toad: toad,
	})
	if err != nil {
		t.Fatal(err)
	}
	kel, _ := founding.GetKel("owner")
	raw, _ := base64.StdEncoding.DecodeString(root.RawBytesB64)
	sig, err := login.SignString(string(raw), seed)
	if err != nil {
		t.Fatal(err)
	}
	icp, _ := json.Marshal(kel.KEL[0])
	owner.AID, owner.NextKeyDigest = root.AID, root.NextKeyDigest
	if err := s.DataStore.SaveIdentity(*owner); err != nil {
		t.Fatal(err)
	}
	if err := s.DataStore.SaveEvent(store.EventRecord{
		AID: root.AID, SequenceNumber: 0, EventType: "icp", EventJSON: string(icp),
		PublicKey: owner.PublicKey, RawBytesB64: root.RawBytesB64, CesrSignature: sig,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ReloadIdentity(&drivers.DriverReloadIdentityRequest{
		AID: root.AID, PublicKey: root.PublicKey, NextKeyDigest: root.NextKeyDigest,
		KEL: kel.KEL, RawEventsB64: kel.RawEventsB64,
	}); err != nil {
		t.Fatal(err)
	}
	return root.AID, e
}

// orgWorld is an organisation that holds its own key, founded as
// foundOrganisation founds it.
func orgWorld(t *testing.T) *CoreServer {
	t.Helper()
	s := agentWithDerivedIdentity(t) // the organisation's key is derivable here
	foundOrganisation(t, s, nil, 0)
	return s
}

// talkSigner is the founder: the owner the test organisation names
// (sealTestOwner), and its one signer on the roster.
const talkSigner = "EOWNERTESTAID"

// controllerWorld is an organisation with a signer on its roster and a
// controller paired to it and granted, served over HTTP as it is in
// production, with its activity log open.
type controllerWorld struct {
	s       *CoreServer
	srv     *httptest.Server
	ctlAID  string
	ctlSeed []byte
}

func newControllerWorld(t *testing.T) *controllerWorld {
	t.Helper()
	s := orgWorld(t)
	if err := s.initAssetHandler(); err != nil {
		t.Fatal(err)
	}
	s.logForTest(t, s.DataDir)
	w := &controllerWorld{s: s}
	// The founder: the owner the organisation names, and its one signer on
	// the roster, as founding makes them.
	w.ctlAID, w.ctlSeed = anAuthorisedMachine(t, s, GradeEnrolled)
	if err := s.assetHandler.Store.UpsertEmployee(asset.Employee{
		PairwiseAID: talkSigner, Name: "Alex", Role: "Owner", Status: "active", IsSigner: true, VouchSig: "0Bvouch",
	}); err != nil {
		t.Fatal(err)
	}
	// Granted as a real one is: anchored. Its signer is settled at first use.
	g, _, _ := s.controllers().Get(w.ctlAID)
	if _, err := s.grantController(g, time.Now().UTC(), coretypes.Authority{}); err != nil {
		t.Fatalf("anchoring the controller's grant: %v", err)
	}
	// The sealed transport replays what it opens through the server's own
	// router, as it does in production.
	s.router = s.buildRouter("")
	w.srv = httptest.NewServer(s.router)
	t.Cleanup(w.srv.Close)
	t.Setenv("PUBLIC_URL", w.srv.URL)
	return w
}

// grantWorld is an organisation that holds its own key, founded and reloaded
// into the engine the way startup reloads it, with its founding event signed and
// stored, and an AI agent delegated from it. Nothing is faked: the grant is
// issued, signed, verified and revoked by the engine that ships.
func grantWorld(t *testing.T) (*CoreServer, *asset.Asset) {
	t.Helper()
	s := agentWithDerivedIdentity(t) // the organisation's key is derivable here
	return foundedWith(t, s, nil, 0)
}

// foundedWith founds the organisation in s, naming witnesses when given, and
// delegates an AI agent from it.
func foundedWith(t *testing.T, s *CoreServer, witnesses []string, toad int) (*CoreServer, *asset.Asset) {
	t.Helper()
	rootAID, e := foundOrganisation(t, s, witnesses, toad)
	aSigner, _ := keri.GenerateSigner(true)
	aNext, _ := keri.GenerateSigner(true)
	aPub, _ := aSigner.PublicKey()
	aNextPub, _ := aNext.PublicKey()
	dip, err := e.CreateDelegatedInception(aPub, aNextPub, "Research assistant", rootAID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.saveDelegationAnchor(rootAID, dip); err != nil {
		t.Fatal(err)
	}
	return s, &asset.Asset{
		ID: "agent-1", DisplayName: "Research assistant", AssetType: "ai_agent",
		PairwiseAID: dip.AID, DelegatorAID: rootAID,
		Capabilities: []string{"infra.zone.list", "system.info.read"},
	}
}
