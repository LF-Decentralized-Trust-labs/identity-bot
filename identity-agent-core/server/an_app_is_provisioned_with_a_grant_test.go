package server

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/authorisation"
	"identity-agent-core/drivers"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/schemas"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// appWorld is a founded identity that holds its own key, with the asset
// handler wired as the server wires it.
func appWorld(t *testing.T) *CoreServer {
	t.Helper()
	s, _ := grantWorld(t)
	if err := s.initAssetHandler(); err != nil {
		t.Fatal(err)
	}
	return s
}

// provisionedApp is an app provisioned by the shipped handler, in a world with
// a founded identity, and the grant the owner issued it.
func provisionedApp(t *testing.T) (*CoreServer, string, string) {
	t.Helper()
	s := appWorld(t)
	app, err := s.assetHandler.ProvisionAppAsset("Task console", []string{"system.info.read", "infra.zone.list"}, nil,
		map[string]interface{}{"infra.zone.list": map[string]interface{}{"zone": []interface{}{"a.example"}}}, nil)
	if err != nil {
		t.Fatalf("provisioning an app: %v", err)
	}
	if app.AssetType != "app" || !strings.HasPrefix(app.Origin, "app://") || app.DelegationModel != "delegated" ||
		app.PairwiseAID == "" || app.DelegatorAID != s.OwnerRootAID() {
		t.Fatalf("the app asset is not an app delegated from the owner: %+v", app)
	}
	said, err := s.issueCapabilityGrant(app, coretypes.Authority{})
	if err != nil {
		t.Fatalf("issuing the App Grant: %v", err)
	}
	return s, app.PairwiseAID, said
}

// The grant issued to an app is an App Grant, held by the app's own identifier,
// issued by the owner, and says capabilities and limits and nothing of a brain.
func TestAnAppIsGivenAnAppGrantFromTheOwner(t *testing.T) {
	s, appAID, said := provisionedApp(t)
	rec, err := s.DataStore.GetCredential(said)
	if err != nil || rec == nil {
		t.Fatalf("the grant is not on record: %v", err)
	}
	if rec.SchemaSAID != schemas.AppGrant.Schema.SAID || rec.HolderAID != appAID || rec.IssuerAID != s.OwnerRootAID() || rec.Status != "issued" {
		t.Fatalf("the grant on record is not the owner's App Grant to the app: %+v", rec)
	}
	acdc, _ := base64.StdEncoding.DecodeString(rec.AcdcJson)
	cred, err := keri.VerifyCredential(acdc)
	if err != nil {
		t.Fatal(err)
	}
	var a map[string]json.RawMessage
	if err := json.Unmarshal(cred.Attributes, &a); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"asset_type", "name", "capabilities", "resource_constraints", "i"} {
		if _, ok := a[k]; !ok {
			t.Fatalf("the App Grant has no %s: %s", k, cred.Attributes)
		}
	}
	for _, k := range []string{"role", "prompt", "model", "messaging", "recipients", "conversation_limits"} {
		if _, ok := a[k]; ok {
			t.Fatalf("an App Grant carries %q, which an app has no use for", k)
		}
	}
	var assetType, name string
	_ = json.Unmarshal(a["asset_type"], &assetType)
	_ = json.Unmarshal(a["name"], &name)
	if assetType != "app" || name != "Task console" {
		t.Fatalf("the App Grant says the wrong thing: %s", cred.Attributes)
	}
	var caps []string
	_ = json.Unmarshal(a["capabilities"], &caps)
	if len(caps) != 2 {
		t.Fatalf("capabilities: %v", caps)
	}
	if err := schemas.AppGrant.CheckAttributes(attributesOf(t, a)); err != nil {
		t.Fatalf("the App Grant issued does not satisfy its own schema: %v", err)
	}
}

func attributesOf(t *testing.T, a map[string]json.RawMessage) map[string]interface{} {
	t.Helper()
	out := map[string]interface{}{}
	for k, v := range a {
		var x interface{}
		if err := json.Unmarshal(v, &x); err != nil {
			t.Fatal(err)
		}
		out[k] = x
	}
	return out
}

// Reissuing an app's grant withdraws the one it replaces, and only an app's
// grant of that app.
func TestReissuingAnAppsGrantWithdrawsTheOldOne(t *testing.T) {
	s, _, first := provisionedApp(t)
	var app asset.Asset
	all, err := s.assetHandler.Store.ListAssets()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range all {
		if a.AssetType == "app" {
			app = a
		}
	}
	second, err := s.issueCapabilityGrant(&app, coretypes.Authority{})
	if err != nil {
		t.Fatal(err)
	}
	if rec, _ := s.DataStore.GetCredential(first); rec == nil || rec.Status == "issued" {
		t.Fatalf("the replaced grant still stands: %+v", rec)
	}
	if rec, _ := s.DataStore.GetCredential(second); rec == nil || rec.Status != "issued" {
		t.Fatalf("the new grant does not stand: %+v", rec)
	}
}

// A device holding the owner's key is shown an App Grant for what it says, and
// the interaction it signs anchors exactly that.
func TestADeviceIsShownAnAppGrantToSign(t *testing.T) {
	s := appWorld(t)
	app, err := s.assetHandler.ProvisionAppAsset("Task console", []string{"system.info.read"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := s.DataStore.GetIdentity()
	registry, err := s.ensureRegistry(owner.AID)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339)
	claims := map[string]interface{}{"name": app.DisplayName, "capabilities": []string{"system.info.read"},
		"asset_type": "app", "valid_until": until,
		"resource_constraints": map[string]interface{}{"system.info.read": map[string]interface{}{"host": []string{"a"}}}}
	p, err := s.KeriDriver.(drivers.PreparedIssuer).PrepareCredentialInRegistry(owner.AID, claims, schemas.AppGrant.Schema.SAID, app.PairwiseAID, nil, registry)
	if err != nil {
		t.Fatal(err)
	}
	shown, err := authorisation.WhatSigningGrants(p.IxnRaw, p.IssRaw, p.AcdcRaw)
	if err != nil {
		t.Fatalf("an App Grant cannot be shown to the device: %v", err)
	}
	if shown.Kind != "app" || shown.Holder != app.PairwiseAID || shown.Name != "Task console" || shown.Issuer != owner.AID ||
		len(shown.Capabilities) != 1 || shown.Capabilities[0] != "system.info.read" || shown.ValidUntil != until ||
		!strings.Contains(string(shown.Limits), `"host":["a"]`) || shown.Revokes {
		t.Fatalf("the device is shown the wrong thing: %+v", shown)
	}
	if !strings.Contains(summaryOf(shown), `the app "Task console"`) {
		t.Fatalf("the one line shown does not say it is an app: %q", summaryOf(shown))
	}
	// An interaction that anchors another credential is not this one.
	other, err := s.KeriDriver.(drivers.PreparedIssuer).PrepareCredentialInRegistry(owner.AID, map[string]interface{}{"name": "other", "capabilities": []string{}, "asset_type": "app"},
		schemas.AppGrant.Schema.SAID, app.PairwiseAID, nil, registry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorisation.WhatSigningGrants(p.IxnRaw, p.IssRaw, other.AcdcRaw); err == nil {
		t.Fatal("an interaction was shown with a credential it does not anchor")
	}
	if grantKindNamed(schemas.AppGrant.Schema.SAID) != schemas.AppGrant {
		t.Fatal("a pending App Grant is not recognised")
	}
}

// An App Grant and an App Body count as grants that name who authorised them,
// so the first-version cutoff is read from them as from an AI agent's.
func TestTheEdgeLookupAcceptsAppSchemas(t *testing.T) {
	for name, said := range map[string]string{
		"App Grant": schemas.AppGrant.Schema.SAID, "App Body": schemas.AppBody.Schema.SAID,
		"AI Agent Grant": schemas.AIAgentGrant.Schema.SAID, "AI Agent Body": schemas.AIAgentBody.Schema.SAID,
		"1.1.0 AI Agent Grant": schemas.AIAgentGrantV11.Schema.SAID,
	} {
		if !isEdgedAssetSchema(said) {
			t.Errorf("%s is not accepted", name)
		}
	}
	for name, said := range map[string]string{
		"first-version AI Agent Grant": schemas.AIAgentGrantV1.Schema.SAID, "Controller Grant": schemas.ControllerGrant.Schema.SAID,
	} {
		if isEdgedAssetSchema(said) {
			t.Errorf("%s is wrongly accepted", name)
		}
	}
	s, appAID, _ := provisionedApp(t)
	since, ok := s.firstEdgedIssuance()
	if !ok || since.IsZero() {
		t.Fatal("an issued App Grant is not found as the first edged issuance")
	}
	// A first-version AI agent credential issued after is dishonoured, as for
	// an identity whose first edged credential was an app's.
	late := &store.CredentialRecord{SchemaSAID: schemas.AIAgentGrantV1.Schema.SAID, HolderAID: appAID,
		IssuedAt: since.Add(time.Hour).Format("2006-01-02T15:04:05.000000000Z07:00")}
	if !s.issuedUnderFirstVersionTooLate(late) {
		t.Fatal("a first-version credential issued after edges began was honoured")
	}
}

// Revoking or removing an app finds its App Grant, as it does an AI agent's
// grant, so the grant does not outlive the app. Finding a grant is not
// admitting it: the schemas a gateway admits do not include the App Grant.
func TestAnAppsGrantIsFoundAndWithdrawnWithTheApp(t *testing.T) {
	s, appAID, said := provisionedApp(t)
	h := hostWrapper{s: s}

	held := h.GrantsHeldBy(appAID, true)
	if len(held) != 1 || held[0].SAID != said {
		t.Fatalf("the app's App Grant is not found among what it holds: %+v", held)
	}
	if g := h.FindCapabilityGrant(appAID); g == nil || g.SAID != said {
		t.Fatalf("FindCapabilityGrant does not find the app's grant: %+v", g)
	}
	for _, admitted := range h.CapabilityGrantSchemaSAIDs() {
		if admitted == schemas.AppGrant.Schema.SAID {
			t.Fatal("looking up an App Grant widened what the gateway admits")
		}
	}

	// What revoking an app does with each grant it holds.
	for _, g := range h.GrantsHeldBy(appAID, true) {
		rec, _ := s.DataStore.GetCredential(g.SAID)
		if _, _, err := h.WithdrawCredential(rec); err != nil {
			t.Fatalf("withdrawing the App Grant: %v", err)
		}
	}
	if rec, _ := s.DataStore.GetCredential(said); rec == nil || rec.Status == "issued" {
		t.Fatalf("the App Grant outlived its app: %+v", rec)
	}
	if left := h.GrantsHeldBy(appAID, true); len(left) != 0 {
		t.Fatalf("a usable grant is still held after revoking: %+v", left)
	}
}

// An app is held to account as an AI agent is: an Identity Agent that holds
// one anchors its record, and the audit trail names its owner.
func TestAnAppCountsAsAnAIAgentDoesForTheRecordAndTheAudit(t *testing.T) {
	s, appAID, _ := provisionedApp(t)
	s.DeclaredEntityType = "individual"
	if !s.anchorsItsRecord() {
		t.Fatal("an Identity Agent that holds an app does not anchor its record")
	}
	name, owner := s.describeAID(appAID)
	if name != "Task console" || owner != s.OwnerRootAID() {
		t.Fatalf("the audit names %q, owner %q; want the app, owned by %q", name, owner, s.OwnerRootAID())
	}
}

// A 1.1.0 grant names who authorised it, so it counts toward when this
// Identity Agent began issuing grants that do, and a first-version grant issued
// after it is not honoured.
func TestAnOlderEdgedGrantCountsAsTheFirstEdgedIssuance(t *testing.T) {
	s := appWorld(t)
	at := time.Now().UTC().Add(-time.Hour)
	if err := s.DataStore.SaveCredential(store.CredentialRecord{SAID: "EOlderGrant", SchemaSAID: schemas.AIAgentGrantV11.Schema.SAID,
		HolderAID: "EHolder", IssuedAt: at.Format("2006-01-02T15:04:05.000000000Z07:00"), Status: "issued"}); err != nil {
		t.Fatal(err)
	}
	since, ok := s.firstEdgedIssuance()
	if !ok || since.IsZero() {
		t.Fatal("an issued 1.1.0 grant is not found as the first edged issuance")
	}
	late := &store.CredentialRecord{SchemaSAID: schemas.AIAgentGrantV1.Schema.SAID, HolderAID: "EHolder2",
		IssuedAt: at.Add(time.Minute).Format("2006-01-02T15:04:05.000000000Z07:00")}
	if !s.issuedUnderFirstVersionTooLate(late) {
		t.Fatal("a first-version grant issued after 1.1.0 grants began was honoured")
	}
}

// What the device signed for an AI agent is kept in the version it was issued
// under.
func TestASignedAIAgentGrantIsKeptUnderItsOwnVersion(t *testing.T) {
	s := appWorld(t)
	owner, _ := s.DataStore.GetIdentity()
	registry, err := s.ensureRegistry(owner.AID)
	if err != nil {
		t.Fatal(err)
	}
	for _, schema := range []string{schemas.AIAgentGrantV11.Schema.SAID, schemas.AIAgentGrant.Schema.SAID} {
		p, err := s.KeriDriver.(drivers.PreparedIssuer).PrepareCredentialInRegistry(owner.AID,
			map[string]interface{}{"name": "Helper", "capabilities": []string{"system.info.read"}, "asset_type": "ai_agent"}, schema, "EHolder", nil, registry)
		if err != nil {
			t.Fatal(err)
		}
		shown, err := authorisation.WhatSigningGrants(p.IxnRaw, p.IssRaw, p.AcdcRaw)
		if err != nil {
			t.Fatal(err)
		}
		if got := schemaSigned(shown); got != schema {
			t.Errorf("a grant issued under %s is kept under %s", schema, got)
		}
	}
}
