package server

import (
	"net/http"
	"testing"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/schemas"
)

// Binding a machine to its app, where the identity's key is on another device,
// asks that device for a grant naming the app, by the same signing request every
// grant there waits on. The machine keeps the grant it has until the device
// signs; then the grant naming the app stands (it is what a conversation bundle
// reads app_asset from) and the one that named no app is withdrawn.
func TestBindingToAnAppAsksTheKeyDeviceForAGrantNamingIt(t *testing.T) {
	w := newControllerWorld(t)
	if err := w.s.assetHandler.Store.UpsertAsset(asset.Asset{ID: "chat", DisplayName: "chat", AssetType: "app", Origin: appPage}); err != nil {
		t.Fatal(err)
	}
	g := aGrant(GradeEnrolled)
	granted, err := w.s.grantController(g, time.Now().UTC(), coretypes.Authority{})
	if err != nil || granted.CredentialSAID == "" {
		t.Fatalf("granting: %+v %v", granted, err)
	}
	w.s.localOwnerSecret = testOwnerSecret
	e := moveTheKeyElsewhere(t, w.s)

	bound, err := w.s.bindAppAsset(g.ControllerAID, "chat")
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	if bound.AppAsset != "chat" || bound.CredentialSAID != granted.CredentialSAID || bound.CredentialPending {
		t.Fatalf("the machine did not keep its grant while the device is asked: %+v", bound)
	}
	reqs := waiting(t, w.s)
	if len(reqs) != 1 || reqs[0].Kind != signingKindGrant {
		t.Fatalf("what the device is asked: %+v", reqs)
	}
	if _, err := checkAsTheDevice(t, w.s, reqs[0]); err != nil {
		t.Fatalf("the device's check: %v", err)
	}
	if rec := fulfil(t, w.s, reqs[0], e.seed); rec.Code != http.StatusOK {
		t.Fatalf("the device's signature: %d %s", rec.Code, rec.Body.String())
	}
	got, _, _ := w.s.controllers().Get(g.ControllerAID)
	if got.CredentialSAID == "" || got.CredentialSAID == granted.CredentialSAID {
		t.Fatalf("the grant naming the app does not stand: %+v", got)
	}
	rec, _ := w.s.DataStore.GetCredential(got.CredentialSAID)
	if rec == nil || rec.SchemaSAID != schemas.ControllerGrant.Schema.SAID {
		t.Fatalf("not a Controller Grant 1.2.0: %+v", rec)
	}
	if attrs, _ := acdcOf(t, w.s, got.CredentialSAID)["a"].(map[string]interface{}); attrs["app_asset"] != "chat" {
		t.Fatalf("the adopted grant does not name the app: %v", attrs["app_asset"])
	}
	if old, _ := w.s.DataStore.GetCredential(granted.CredentialSAID); old == nil || old.Status == "issued" {
		t.Fatalf("the grant that named no app still stands: %+v", old)
	}
	if err := w.s.rowIsItsGrant(got); err != nil {
		t.Fatalf("the row no longer matches its grant: %v", err)
	}
	keyLogVerifies(t, w.s)
}

// The exception is that one grant and no wider: with no signed request, a
// grant that is anything else is refused whether it is asked for or signed.
func TestOnlyANamingOfTheAppWaitsWithNoRequest(t *testing.T) {
	w := newControllerWorld(t)
	if err := w.s.assetHandler.Store.UpsertAsset(asset.Asset{ID: "chat", DisplayName: "chat", AssetType: "app", Origin: appPage}); err != nil {
		t.Fatal(err)
	}
	g := aGrant(GradeEnrolled)
	granted, err := w.s.grantController(g, time.Now().UTC(), coretypes.Authority{})
	if err != nil {
		t.Fatal(err)
	}
	w.s.localOwnerSecret = testOwnerSecret
	moveTheKeyElsewhere(t, w.s)
	if _, err := w.s.bindAppAsset(g.ControllerAID, "chat"); err != nil {
		t.Fatal(err)
	}
	pending := func() grantSpec { _, p := waitingGrant(t, w.s); return p.Spec }
	spec := pending()
	if spec.Request != nil || spec.RegrantOf != granted.CredentialSAID {
		t.Fatalf("the waiting grant: %+v", spec)
	}
	for name, edit := range map[string]func(*grantSpec){
		"no grant named to replace": func(s *grantSpec) { s.RegrantOf = "" },
		"another grant to replace":  func(s *grantSpec) { s.RegrantOf = "Eother" },
		"another grade":             func(s *grantSpec) { s.Claims = withClaim(s.Claims, "grade", "owner") },
		"another key":               func(s *grantSpec) { s.Claims = withClaim(s.Claims, "public_key", "Dother") },
		"a signer added":            func(s *grantSpec) { s.Claims = withClaim(s.Claims, "signer", "Esomeone") },
		"another app":               func(s *grantSpec) { s.Claims = withClaim(s.Claims, "app_asset", "another") },
		"no app":                    func(s *grantSpec) { s.Claims = withClaim(s.Claims, "app_asset", "") },
		"a claim added":             func(s *grantSpec) { s.Claims = withClaim(s.Claims, "extra", "x") },
		"another holder":            func(s *grantSpec) { s.Holder = "Eother" },
	} {
		s := pending()
		edit(&s)
		if err := w.s.mayWaitWithoutARequest(signingKindGrant, s); err == nil {
			t.Errorf("%s: a grant with no request was allowed to wait", name)
		}
	}
	if err := w.s.mayWaitWithoutARequest(signingKindRegistry, spec); err == nil {
		t.Error("a registry's inception was allowed to wait with no request")
	}
	if err := w.s.mayWaitWithoutARequest(signingKindGrant, spec); err != nil {
		t.Errorf("the naming of the app itself was refused: %v", err)
	}
	// A new machine, or any grant asked for with no request and no grant to
	// replace, is still refused.
	if _, err := w.s.grantController(grantFor(9, GradeEnrolled), time.Now().UTC(), coretypes.Authority{}); err == nil {
		t.Error("a new machine was granted with no request, the key being elsewhere")
	}
}

func withClaim(in map[string]interface{}, k string, v interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for a, b := range in {
		out[a] = b
	}
	out[k] = v
	return out
}
