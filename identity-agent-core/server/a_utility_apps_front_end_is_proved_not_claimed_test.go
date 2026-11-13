package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/asset"
	"identity-agent-core/login"
)

// postASession is a web page starting a sign-in at the public page route, with
// the Origin header its browser sends.
func postASession(t *testing.T, w *aWebsiteWorld, origin, body string) (int, string) {
	t.Helper()
	r := chi.NewRouter()
	w.org.mountLoginWidgetRoutes(r)
	req := httptest.NewRequest("POST", "/api/login/session/the-website", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// Fails without the proof an installed app must carry: a page that calls itself
// the installed app must not get round a switched-off browser, nor be let in
// as an installed app at all while no installed-app key exists.
func TestAPageCannotCallItselfTheInstalledApp(t *testing.T) {
	w := anAppOffering(t, []string{"browser", "installed_app"}, []string{"browser"})
	code, body := postASession(t, w, "https://portal.example", `{"frontEnd":"installed_app"}`)
	if code != http.StatusForbidden || strings.Contains(body, "collector_secret") {
		t.Fatalf("a page named itself the installed app and got %d %s", code, body)
	}
	// Even with the installed app on and the browser on, no key, no sign-in.
	w = anAppOffering(t, []string{"browser", "installed_app"}, nil)
	for _, origin := range []string{"https://portal.example", ""} {
		code, body := postASession(t, w, origin, `{"frontEnd":"installed_app"}`)
		if code != http.StatusForbidden || strings.Contains(body, "collector_secret") {
			t.Fatalf("origin %q: installed_app got %d %s", origin, code, body)
		}
		if origin == "" && !strings.Contains(body, "utility app's installed front end") {
			t.Fatalf("the refusal does not name the kind of app: %s", body)
		}
	}
	// The gate is the key, not the word: with the key presented it is let through.
	if _, _, code, msg := w.org.createSignedAssetChallenge("the-website", "https://portal.example", "", nil, "", "installed_app", w.srv.URL, true); code != 0 {
		t.Fatalf("an installed app carrying its key was refused: %d %s", code, msg)
	}
}

// Fails without the Origin rule: a request from a web page is a browser's.
func TestAPageIsABrowserAndNothingElse(t *testing.T) {
	w := anAppOffering(t, []string{"browser", "installed_app"}, nil)
	if code, body := postASession(t, w, "https://portal.example", `{"frontEnd":"browser"}`); code != http.StatusOK || !strings.Contains(body, "collector_secret") {
		t.Fatalf("a page's browser sign-in got %d %s", code, body)
	}
	// An installed app's key presented to a page route does not make the page
	// an installed app either.
	if _, _, code, _ := w.org.createSignedAssetChallenge("the-website", "https://portal.example", "https://portal.example", nil, "", "installed_app", w.srv.URL, true); code != http.StatusForbidden {
		t.Fatalf("a request with a browser Origin was let in as an installed app: %d", code)
	}
	// A page that names no kind of a declared app is refused, as before.
	if code, _ := postASession(t, w, "https://portal.example", `{}`); code != http.StatusForbidden {
		t.Fatalf("a page naming no front end got %d", code)
	}
	// A switched-off browser stays off for a page.
	w = anAppOffering(t, []string{"browser", "installed_app"}, []string{"browser"})
	if code, _ := postASession(t, w, "https://portal.example", `{"frontEnd":"browser"}`); code != http.StatusForbidden {
		t.Fatalf("a switched-off browser let a page in: %d", code)
	}
}

// The signed challenge names the kind; the person's assertion repeats it.
func TestTheChallengeNamesTheFrontEndAndTheAssertionRepeatsIt(t *testing.T) {
	w := anAppOffering(t, []string{"browser"}, nil)
	h := aPersonsIdentityAgent(t)
	token, _, code, msg := w.org.createSignedAssetChallenge("the-website", "https://portal.example", "", []string{"display_name"}, "", "browser", w.srv.URL, false)
	if code != 0 {
		t.Fatalf("no challenge: %d %s", code, msg)
	}
	req := login.StartLoginRequest{SessionToken: token, RPSessionURL: w.srv.URL}
	bundle := w.org.challenges[token]
	if bundle.FrontEnd != "browser" {
		t.Fatalf("the challenge names %q", bundle.FrontEnd)
	}
	preview, err := h.Preview(req)
	if err != nil || preview.FrontEnd != "browser" {
		t.Fatalf("the person's consent does not name the kind: %+v %v", preview, err)
	}
	if _, err := h.Approve(req); err != nil {
		t.Fatalf("approving: %v", err)
	}
	w.org.challengeMu.Lock()
	got := w.org.challengeStatus[token]["front_end"]
	w.org.challengeMu.Unlock()
	if got != "browser" || theStatus(w, token) != "complete" {
		t.Fatalf("the result carries front_end %v, status %v", got, theStatus(w, token))
	}
}

// An assertion approved for another kind, or for none, is refused at the callback.
func TestAnAssertionForAnotherFrontEndIsRefusedAtTheCallback(t *testing.T) {
	for name, wrong := range map[string]string{"another kind": "installed_app", "no kind": ""} {
		t.Run(name, func(t *testing.T) {
			w := anAppOffering(t, []string{"browser", "installed_app"}, nil)
			h := aPersonsIdentityAgent(t)
			token, _, code, msg := w.org.createSignedAssetChallenge("the-website", "https://portal.example", "", nil, "", "browser", w.srv.URL, false)
			if code != 0 {
				t.Fatalf("no challenge: %d %s", code, msg)
			}
			bundle := w.org.challenges[token]
			forged := bundle
			forged.FrontEnd = wrong
			rel, err := h.GetOrCreateRelationship(bundle.SiteAID, &bundle)
			if err != nil {
				t.Fatal(err)
			}
			a, err := h.BuildAssertion(rel, &forged, nil)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(a)
			resp, err := http.Post(w.srv.URL+"/api/login/callback?session="+token, "application/json", bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), "front end mismatch") {
				t.Fatalf("answered %d %s", resp.StatusCode, body)
			}
			if theStatus(w, token) != "pending" {
				t.Fatalf("the session is %v", theStatus(w, token))
			}
		})
	}
}

// Fails without the second check: a challenge issued just before the owner
// switched the browser off must not be approved after it.
func TestAChallengeIssuedBeforeASwitchOffIsNotApprovedAfterIt(t *testing.T) {
	w := anAppOffering(t, []string{"browser"}, nil)
	h := aPersonsIdentityAgent(t)
	token, _, code, msg := w.org.createSignedAssetChallenge("the-website", "https://portal.example", "", nil, "", "browser", w.srv.URL, false)
	if code != 0 {
		t.Fatalf("no challenge: %d %s", code, msg)
	}
	a, _, _ := w.org.assetHandler.Store.GetAsset("the-website")
	a.FrontEndsOff = []string{"browser"}
	if err := w.org.assetHandler.Store.UpsertAsset(a); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Approve(login.StartLoginRequest{SessionToken: token, RPSessionURL: w.srv.URL}); err == nil {
		t.Fatal("a sign-in begun before the switch-off was approved after it")
	}
	if got := theStatus(w, token); got == "complete" {
		t.Fatal("the session completed")
	}
	// Switched back on, the same challenge finishes: the setting is read, not remembered.
	a.FrontEndsOff = nil
	_ = w.org.assetHandler.Store.UpsertAsset(a)
	if _, err := h.Approve(login.StartLoginRequest{SessionToken: token, RPSessionURL: w.srv.URL}); err != nil {
		t.Fatalf("after switching back on: %v", err)
	}
}

// An app made before it could declare signs in as it always did: no kind
// needed, none named in the challenge, and a page's sign-in works.
func TestAnOlderAppSignsInAsBefore(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	a, _, _ := w.org.assetHandler.Store.GetAsset("the-website")
	a.AssetType = "app"
	if err := w.org.assetHandler.Store.UpsertAsset(a); err != nil {
		t.Fatal(err)
	}
	if code, body := postASession(t, w, "https://portal.example", `{}`); code != http.StatusOK {
		t.Fatalf("an older app's page sign-in got %d %s", code, body)
	}
	token, _, code, _ := w.org.createSignedAssetChallenge("the-website", "https://portal.example", "", nil, aBrowserKey, "", w.srv.URL, false)
	if code != 0 || w.org.challenges[token].FrontEnd != "browser" {
		t.Fatalf("a browser key's sign-in to an older app: %d, names %q", code, w.org.challenges[token].FrontEnd)
	}
	// Still no installed app without its key, declared or not.
	if code, _ := postASession(t, w, "", `{"frontEnd":"installed_app"}`); code != http.StatusForbidden {
		t.Fatalf("an older app let installed_app in without a key: %d", code)
	}
	// Declared none, it refuses everything.
	a.FrontEndsDeclared, a.DeviceFrontEnds = true, []string{}
	_ = w.org.assetHandler.Store.UpsertAsset(a)
	if code, _ := postASession(t, w, "https://portal.example", `{}`); code != http.StatusForbidden {
		t.Fatalf("an app declaring none signed a page in: %d", code)
	}
}

// ProvisionAppAsset, the ADR-045 delegated-app path, takes the list.
func TestProvisionAppAssetTakesAFrontEndList(t *testing.T) {
	s := appWorld(t)
	a, err := s.assetHandler.ProvisionAppAsset("Lister", []string{"system.info.read"}, nil, nil, []string{"browser"})
	if err != nil || !a.FrontEndsAreDeclared() || a.FrontEndRefusal("installed_app") == "" || a.FrontEndRefusal("browser") != "" {
		t.Fatalf("a declared list: %+v %v", a, err)
	}
	a, err = s.assetHandler.ProvisionAppAsset("Nothing", []string{"system.info.read"}, nil, nil, []string{})
	if err != nil || a.FrontEndRefusal("browser") == "" {
		t.Fatalf("a declared-empty list: %+v %v", a, err)
	}
	a, err = s.assetHandler.ProvisionAppAsset("Undeclared", []string{"system.info.read"}, nil, nil, nil)
	if err != nil || a.FrontEndsAreDeclared() || a.FrontEndRefusal("browser") != "" {
		t.Fatalf("no list: %+v %v", a, err)
	}
	got, _, _ := s.assetHandler.Store.GetAsset(a.ID)
	if got.FrontEndsAreDeclared() {
		t.Fatalf("stored as declared: %+v", got)
	}
}

// The owner names the installed program when the app is provisioned, and only
// for an app that offers an installed front end.
func TestProvisionAppAssetKeepsTheProgramItsOwnerNamed(t *testing.T) {
	s := appWorld(t)
	id := asset.InstalledAppIdentity{AppleAppID: "TEAM123456.org.example.portal"}
	a, err := s.assetHandler.ProvisionAppAssetNamingItsProgram("Named", []string{"system.info.read"}, nil, nil, []string{"installed_app"}, id)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.assetHandler.Store.GetAsset(a.ID); got.InstalledApp.AppleAppID != id.AppleAppID {
		t.Fatalf("the program the owner named was not kept: %+v", got.InstalledApp)
	}
	if _, err := s.assetHandler.ProvisionAppAssetNamingItsProgram("Browser only", []string{"system.info.read"}, nil, nil, []string{"browser"}, id); err == nil {
		t.Fatal("an installed program was named for an app with no installed front end")
	}
}

// A paired controller reads the setting and cannot change it.
func TestAControllerMayReadFrontEndsButNotChangeThem(t *testing.T) {
	for _, route := range []string{"PUT /api/assets/{id}/front-ends", "PUT /api/assets/{id}/front-ends/offered"} {
		if _, ok := controllerOwnerOnly[route]; !ok {
			t.Errorf("%s is not owner-only", route)
		}
	}
	if _, ok := controllerOwnerOnly["GET /api/assets/{id}/front-ends"]; ok {
		t.Error("reading the setting is closed to a controller")
	}
}
