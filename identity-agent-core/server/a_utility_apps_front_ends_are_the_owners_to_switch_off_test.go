package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/asset"
)

// anAppOffering is the website made into a utility app that offers the given
// front ends, with the given ones switched off by its owner.
func anAppOffering(t *testing.T, offered, off []string) *aWebsiteWorld {
	t.Helper()
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	a, _, err := w.org.assetHandler.Store.GetAsset("the-website")
	if err != nil {
		t.Fatal(err)
	}
	a.AssetType, a.DeviceFrontEnds, a.FrontEndsOff, a.FrontEndsDeclared = "app", offered, off, true
	if err := w.org.assetHandler.Store.UpsertAsset(a); err != nil {
		t.Fatal(err)
	}
	return w
}

// theChallengeFor asks as a caller that carries the installed app's own key, so
// the rules tested with it are the offered list and the owner's switches alone;
// what a request must prove to be an installed app is tested apart (see
// TestAPageCannotCallItselfTheInstalledApp).
func theChallengeFor(w *aWebsiteWorld, key, frontEnd string) (int, string) {
	_, _, code, msg := w.org.createSignedAssetChallenge("the-website", "https://portal.example", "", nil, key, frontEnd, w.srv.URL, true)
	return code, msg
}

func TestAnAppIssuesAChallengeForAFrontEndItOffersAndIsNotSwitchedOff(t *testing.T) {
	w := anAppOffering(t, []string{"browser", "installed_app"}, []string{"installed_app"})
	if code, msg := theChallengeFor(w, aBrowserKey, "browser"); code != 0 {
		t.Fatalf("a browser sign-in to an app offering one was refused: %d %s", code, msg)
	}
	// A browser key with no kind named is a browser's.
	if code, msg := theChallengeFor(w, aBrowserKey, ""); code != 0 {
		t.Fatalf("a sign-in for a browser's key was refused: %d %s", code, msg)
	}
}

// Fails without the "offered" check: an app that offers only a browser must
// not sign anyone in to an installed app.
func TestAnAppRefusesAFrontEndItDoesNotOffer(t *testing.T) {
	w := anAppOffering(t, []string{"browser"}, nil)
	code, msg := theChallengeFor(w, "", "installed_app")
	if code != http.StatusForbidden || !strings.Contains(msg, "does not offer") {
		t.Fatalf("got %d %q, want 403 saying the app does not offer it", code, msg)
	}
	// An app that has declared nothing offers nothing.
	w = anAppOffering(t, nil, nil)
	if code, _ := theChallengeFor(w, aBrowserKey, "browser"); code != http.StatusForbidden {
		t.Fatalf("an app declaring no front ends issued a challenge: %d", code)
	}
}

// Fails without the "switched off" check, and says whose doing it is.
func TestAnAppRefusesAFrontEndItsOwnerSwitchedOff(t *testing.T) {
	w := anAppOffering(t, []string{"browser", "installed_app"}, []string{"browser"})
	code, msg := theChallengeFor(w, aBrowserKey, "browser")
	if code != http.StatusForbidden || !strings.Contains(msg, "switched off") {
		t.Fatalf("got %d %q, want 403 saying the owner switched it off", code, msg)
	}
	if code, msg := theChallengeFor(w, "", "installed_app"); code != 0 {
		t.Fatalf("the front end still on was refused: %d %s", code, msg)
	}
}

// Fails without the "kind is named" check: a request that names no kind and no
// browser key must not slip past the setting.
func TestAnAppRefusesASignInThatNamesNoFrontEnd(t *testing.T) {
	w := anAppOffering(t, []string{"browser", "installed_app"}, nil)
	for _, bad := range []string{"", "tablet"} {
		code, msg := theChallengeFor(w, "", bad)
		if code != http.StatusForbidden || !strings.Contains(msg, "does not say which front end") {
			t.Fatalf("front end %q: %d %q, want 403 asking which front end", bad, code, msg)
		}
	}
}

// The setting is on the route a front end uses, not only on the helper.
func TestTheLoginRoutesCarryTheFrontEndSetting(t *testing.T) {
	w := anAppOffering(t, []string{"browser", "installed_app"}, []string{"installed_app"})
	for fe, want := range map[string]int{"installed_app": http.StatusForbidden, "browser": http.StatusOK} {
		req := httptest.NewRequest("POST", "/api/login/challenge", strings.NewReader(
			`{"asset_id":"the-website","audience":"https://portal.example","front_end":"`+fe+`","browser_key":"`+aBrowserKey+`"}`))
		rec := httptest.NewRecorder()
		w.org.handleCreateAssetChallenge(rec, req)
		if rec.Code != want {
			t.Fatalf("front_end %s answered %d, want %d: %s", fe, rec.Code, want, rec.Body)
		}
	}
}

// A website asset is not a utility app and has no front-end setting.
func TestAnAssetThatIsNotAnAppIsNotAskedForAFrontEnd(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	if code, msg := theChallengeFor(w, "", ""); code != 0 {
		t.Fatalf("a website's sign-in was refused: %d %s", code, msg)
	}
}

// Fails without forcing a browser key's sign-in to be a browser's: naming
// another kind must not get round a switched-off browser front end.
func TestABrowserKeyCannotSignInAsAnotherFrontEnd(t *testing.T) {
	w := anAppOffering(t, []string{"browser", "installed_app"}, []string{"browser"})
	if code, _ := theChallengeFor(w, aBrowserKey, "installed_app"); code != http.StatusForbidden {
		t.Fatalf("a browser key signed in as an installed app: %d", code)
	}
	if code, _ := theChallengeFor(w, aBrowserKey, "browser"); code != http.StatusForbidden {
		t.Fatalf("a switched-off browser front end signed in: %d", code)
	}
}
