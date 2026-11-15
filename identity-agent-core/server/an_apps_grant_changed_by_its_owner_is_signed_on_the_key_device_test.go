package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"identity-agent-core/authorisation"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/login"
	"identity-agent-core/schemas"
)

// theOwnerAsksToChange is the owner's signed request to change what an
// existing app's grant gives, as the route that takes it sends it: the app is
// named in the path, and the capabilities asked for are in the body.
func theOwnerAsksToChange(t *testing.T, s *CoreServer, assetID string, caps []string) coretypes.Authority {
	t.Helper()
	identity, _ := s.DataStore.GetIdentity()
	seed, err := s.identitySigningSeed()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]interface{}{"capabilities": caps})
	path := "/api/hosted-apps/" + assetID + "/capabilities"
	signed := canonicalOwnerRequest(identity.AID, "PUT", path, time.Now().UTC().Format(time.RFC3339), body)
	sig, err := login.SignString(signed, seed)
	if err != nil {
		t.Fatal(err)
	}
	return coretypes.Authority{About: assetID, Request: &coretypes.SignedRequest{
		Kind: "owner", Signer: identity.AID, Signed: signed, Signature: sig, Body: string(body)}}
}

func anAddonIssuingAppGrants(t *testing.T) {
	t.Helper()
	onlyAddons(t, Addon{Name: "test apps", GrantKinds: map[*schemas.AssetGrant]GrantKind{
		schemas.AppGrant: {StillWhatItGrants: func(*CoreServer, *authorisation.ToSign) error { return nil }},
	}})
}

// Where the owner's key is on another device, an app's changed grant waits for
// that device to sign it. The grant standing stays in force until the new one
// does, and is withdrawn (asked of that device too) once the new one stands:
// never two in force, and never the old withdrawn while the new one is unsigned.
func TestAnAppGrantTheOwnerChangesIsSignedOnTheKeyDeviceAndReplacesTheOldOne(t *testing.T) {
	anAddonIssuingAppGrants(t)
	s := appWorld(t)
	app, err := s.assetHandler.ProvisionAppAsset("Task console", []string{"app.network.request"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldSAID, err := s.issueCapabilityGrant(app, coretypes.Authority{})
	if err != nil {
		t.Fatalf("the app's first grant: %v", err)
	}
	// The change, asked while the key is still readable here to sign the request,
	// then the key moves to the device that will sign the grant.
	widened := *app
	widened.Capabilities = []string{"app.network.request", "ai_agent.watch_feed"}
	by := theOwnerAsksToChange(t, s, app.ID, widened.Capabilities)
	e := moveTheKeyElsewhere(t, s)
	if _, err := s.issueCapabilityGrant(&widened, by); !errors.Is(err, errKeyElsewhere) {
		t.Fatalf("a changed grant for the device to sign was answered %v", err)
	}
	if held := s.capabilityGrantsStanding(schemas.AppGrant, app.PairwiseAID); len(held) != 1 || held[0].SAID != oldSAID {
		t.Fatalf("the grant standing is not the old one while the new waits: %+v", held)
	}
	req, p := waitingGrant(t, s)
	if p.Spec.Holder != app.PairwiseAID || p.Spec.About != app.ID {
		t.Fatalf("what waits: %+v", p.Spec)
	}
	shown, err := checkAsTheDevice(t, s, req)
	if err != nil {
		t.Fatalf("the device's check: %v", err)
	}
	if shown["kind"] != "app" {
		t.Fatalf("the device is shown %v", shown)
	}
	if rec := fulfil(t, s, req, e.seed); rec.Code != http.StatusOK {
		t.Fatalf("the device's signature: %d %s", rec.Code, rec.Body.String())
	}
	held := s.capabilityGrantsStanding(schemas.AppGrant, app.PairwiseAID)
	if len(held) != 1 || held[0].SAID == oldSAID {
		t.Fatalf("after the device signed, the grants in force are %+v, not the one new grant", held)
	}
	if old, _ := s.DataStore.GetCredential(oldSAID); old == nil || isUsableStatus(old.Status) {
		t.Fatalf("the old grant is still in force: %+v", old)
	}
	// Its withdrawal is the device's to sign too.
	var asked bool
	for _, r := range waiting(t, s) {
		asked = asked || r.Kind == signingKindRevocation
	}
	if !asked {
		t.Fatal("the device was not asked to withdraw the grant it replaced")
	}
	keyLogVerifies(t, s)
}

// Refused on the device, the change leaves the grant standing as it was.
func TestAnAppGrantTheDeviceRefusesLeavesTheOldOneInForce(t *testing.T) {
	anAddonIssuingAppGrants(t)
	s := appWorld(t)
	app, _ := s.assetHandler.ProvisionAppAsset("Task console", []string{"app.network.request"}, nil, nil, nil)
	oldSAID, err := s.issueCapabilityGrant(app, coretypes.Authority{})
	if err != nil {
		t.Fatal(err)
	}
	widened := *app
	widened.Capabilities = []string{"app.network.request", "ai_agent.watch_feed"}
	by := theOwnerAsksToChange(t, s, app.ID, widened.Capabilities)
	moveTheKeyElsewhere(t, s)
	if _, err := s.issueCapabilityGrant(&widened, by); !errors.Is(err, errKeyElsewhere) {
		t.Fatal(err)
	}
	s.withdrawWaitingFor(app.PairwiseAID)
	if held := s.capabilityGrantsStanding(schemas.AppGrant, app.PairwiseAID); len(held) != 1 || held[0].SAID != oldSAID {
		t.Fatalf("a change nobody signed took the old grant away: %+v", held)
	}
}
