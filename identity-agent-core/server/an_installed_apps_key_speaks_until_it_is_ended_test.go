package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/asset"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"
)

// An installed app holds its key in its device's secure hardware, and the
// core accepts that only on a hardware attestation it verifies itself, held to
// the program the owner named. These tests stand in for the hardware vendors'
// signatures (their verifiers are tested in secureenclave) and test what the
// core decides with what they say.

const theAndroidPackage = "org.example.portal"

var theAndroidSigner = strings.Repeat("ab", 32)

type anInstalledAppWorld struct {
	*aWebsiteWorld
	key  string
	pub  *ecdsa.PublicKey
	said *secureenclave.InstalledAppKeyFacts // what the stand-in hardware says
}

func anInstalledAppsWorld(t *testing.T, offered, off []string) *anInstalledAppWorld {
	t.Helper()
	w := anAppOffering(t, offered, off)
	a, _, _ := w.org.assetHandler.Store.GetAsset("the-website")
	a.InstalledApp = asset.InstalledAppIdentity{AndroidPackage: theAndroidPackage, AndroidSigners: []string{theAndroidSigner}, AppleAppID: "TEAM123456.org.example.portal"}
	if err := w.org.assetHandler.Store.UpsertAsset(a); err != nil {
		t.Fatal(err)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tp, err := thumbprintOfECKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	iw := &anInstalledAppWorld{aWebsiteWorld: w, key: tp, pub: &k.PublicKey}
	signer := bytes.Repeat([]byte{0xab}, 32)
	iw.said = &secureenclave.InstalledAppKeyFacts{Public: &k.PublicKey, Platform: "android", Level: "strongbox",
		AppPackages: []string{theAndroidPackage}, AppSigners: [][]byte{signer}, AppIDPresent: true}
	stand := func(wantPlatform string) {
		fake := func(ev, ch []byte, now time.Time) (*secureenclave.InstalledAppKeyFacts, error) {
			if !bytes.Equal(ch, InstalledAppKeyChallenge("the-website")) {
				return nil, errors.New("not the challenge of this asset")
			}
			return iw.said, nil
		}
		verifyAndroidInstalledKey = fake
		verifyAppleInstalledKey = func(ev, ch []byte, appID string, now time.Time) (*secureenclave.InstalledAppKeyFacts, error) {
			if appID != "TEAM123456.org.example.portal" {
				return nil, errors.New("not the owner's app id")
			}
			return fake(ev, ch, now)
		}
		verifyTPMInstalledKey = fake
	}
	oa, oap, ot := verifyAndroidInstalledKey, verifyAppleInstalledKey, verifyTPMInstalledKey
	t.Cleanup(func() { verifyAndroidInstalledKey, verifyAppleInstalledKey, verifyTPMInstalledKey = oa, oap, ot })
	stand("")
	return iw
}

func (iw *anInstalledAppWorld) proof() *InstalledAppKeyProof {
	return &InstalledAppKeyProof{Platform: iw.said.Platform, Evidence: []byte("evidence")}
}

// anAppsRequest is a request an app's back end signed, as the core sees it.
func anAppsRequest(assetID string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/addon/sign-in", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), appContextKey{}, AppCaller{Asset: assetID}))
}

func (iw *anInstalledAppWorld) start(r *http.Request, assetID string, p *InstalledAppKeyProof) (BrowserKeySignIn, error) {
	return iw.org.startFrontEndKeySignIn(r, "", assetID, "https://portal.example", iw.key, "installed_app", iw.srv.URL, p)
}

func (iw *anInstalledAppWorld) signedIn(t *testing.T) {
	t.Helper()
	in, err := iw.start(anAppsRequest("the-website", nil), "the-website", iw.proof())
	if err != nil {
		t.Fatal(err)
	}
	h := aPersonsIdentityAgent(t)
	if _, err := h.Approve(login.StartLoginRequest{SessionToken: in.Session, RPSessionURL: iw.srv.URL}); err != nil {
		t.Fatalf("an approved sign-in was refused: %v", err)
	}
}

func TestAProvedInstalledAppsSignInSpeaksUntilItIsEndedAndABrowsersLapses(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	long := time.Now().Add(100 * 24 * time.Hour)
	iw.signedIn(t)
	if _, ok := iw.org.browserKeys().Whose("the-website", iw.key, time.Now()); !ok {
		t.Fatal("the proved key does not speak after its sign-in")
	}
	if _, ok := iw.org.browserKeys().Whose("the-website", iw.key, long); !ok {
		t.Fatal("an app-key grant lapsed")
	}
	grants := iw.org.browserKeys().AppKeyGrants("the-website", time.Now())
	if len(grants) != 1 || grants[0].Proof == nil || grants[0].Proof.Platform != "android" || grants[0].Proof.Level != "strongbox" {
		t.Fatalf("the grant does not say how its key was proved: %+v", grants)
	}
	// A browser's session still lapses.
	in, err := iw.org.startFrontEndKeySignIn(anAppsRequest("the-website", nil), "", "the-website", "x", aBrowserKey, "browser", iw.srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aPersonsIdentityAgent(t).Approve(login.StartLoginRequest{SessionToken: in.Session, RPSessionURL: iw.srv.URL}); err != nil {
		t.Fatal(err)
	}
	if _, ok := iw.org.browserKeys().Whose("the-website", aBrowserKey, long); ok {
		t.Fatal("a browser's session did not lapse")
	}
}

// Naming the kind is not proof: each of these is refused, and the refusal is
// the core's own, made before any sign-in exists.
func TestAnInstalledAppSignInRestsOnProofAndNotOnTheCallersWord(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, c := range map[string]struct {
		req   *http.Request
		asset string
		proof *InstalledAppKeyProof
		mod   func()
	}{
		"no proof":                           {req: anAppsRequest("the-website", nil), asset: "the-website"},
		"empty evidence":                     {req: anAppsRequest("the-website", nil), asset: "the-website", proof: &InstalledAppKeyProof{Platform: "android"}},
		"a request no app signed":            {req: httptest.NewRequest("POST", "/x", nil), asset: "the-website", proof: iw.proof()},
		"another app's asset":                {req: anAppsRequest("some-other-app", nil), asset: "the-website", proof: iw.proof()},
		"a page, by Origin":                  {req: anAppsRequest("the-website", map[string]string{"Origin": "https://evil.example"}), asset: "the-website", proof: iw.proof()},
		"a page, by Fetch Metadata":          {req: anAppsRequest("the-website", map[string]string{"Sec-Fetch-Mode": "cors"}), asset: "the-website", proof: iw.proof()},
		"an unknown platform":                {req: anAppsRequest("the-website", nil), asset: "the-website", proof: &InstalledAppKeyProof{Platform: "toaster", Evidence: []byte("x")}},
		"another key than the attested":      {req: anAppsRequest("the-website", nil), asset: "the-website", proof: iw.proof(), mod: func() { iw.said.Public = &other.PublicKey }},
		"another package":                    {req: anAppsRequest("the-website", nil), asset: "the-website", proof: iw.proof(), mod: func() { iw.said.AppPackages = []string{"org.evil"} }},
		"another signing certificate":        {req: anAppsRequest("the-website", nil), asset: "the-website", proof: iw.proof(), mod: func() { iw.said.AppSigners = [][]byte{bytes.Repeat([]byte{1}, 32)} }},
		"no program stated":                  {req: anAppsRequest("the-website", nil), asset: "the-website", proof: iw.proof(), mod: func() { iw.said.AppIDPresent, iw.said.AppPackages = false, nil }},
		"a TPM key the owner did not accept": {req: anAppsRequest("the-website", nil), asset: "the-website", proof: &InstalledAppKeyProof{Platform: "tpm", Evidence: []byte("x")}, mod: func() { iw.said.Platform = "tpm" }},
		"a platform that vouches as another": {req: anAppsRequest("the-website", nil), asset: "the-website", proof: &InstalledAppKeyProof{Platform: "apple", Evidence: []byte("x")}},
	} {
		t.Run(name, func(t *testing.T) {
			saved := *iw.said
			defer func() { *iw.said = saved }()
			if c.mod != nil {
				c.mod()
			}
			_, err := iw.start(c.req, c.asset, c.proof)
			var refused *SignInRefused
			if !errors.As(err, &refused) {
				t.Fatalf("started: %v", err)
			}
		})
	}
	// An owner who named nothing accepts no installed-app key at all.
	a, _, _ := iw.org.assetHandler.Store.GetAsset("the-website")
	a.InstalledApp = asset.InstalledAppIdentity{}
	_ = iw.org.assetHandler.Store.UpsertAsset(a)
	if _, err := iw.start(anAppsRequest("the-website", nil), "the-website", iw.proof()); err == nil {
		t.Fatal("an installed-app key was accepted for an app whose owner named no program")
	}
}

func TestAPublicRouteCannotStartAnInstalledAppSignIn(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	_, _, code, _ := iw.org.createSignedAssetChallenge("the-website", "https://portal.example", "", nil, iw.key, "installed_app", iw.srv.URL, false)
	if code != http.StatusForbidden {
		t.Fatalf("a public route started an installed-app sign-in: %d", code)
	}
}

// A browser sign-in through the host is still the caller's own app's.
func TestABrowserSignInIsForTheCallingAppsOwnAssetToo(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	if _, err := iw.org.startFrontEndKeySignIn(anAppsRequest("some-other-app", nil), "", "the-website", "x", aBrowserKey, "browser", iw.srv.URL, nil); err == nil {
		t.Fatal("an app started a browser sign-in for another app's asset")
	}
}

func TestSwitchingOffTheInstalledAppFrontEndStopsAGrantAtOnceAndEndsIt(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	iw.signedIn(t)
	roster := keysSpeakingAt{s: iw.org, asset: "the-website"}
	person, _ := iw.org.browserKeys().Whose("the-website", iw.key, time.Now())
	verkey := aMachineVerkeyOf(t, iw.pub)
	if !roster.KeySpeaksFor(person, "", verkey) {
		t.Fatal("the grant does not speak before the owner switches the front end off")
	}
	a, _, _ := iw.org.assetHandler.Store.GetAsset("the-website")
	a.FrontEndsOff = []string{"installed_app"}
	_ = iw.org.assetHandler.Store.UpsertAsset(a)
	if roster.KeySpeaksFor(person, "", verkey) {
		t.Fatal("a grant kept speaking after the owner switched its front end off, which is checked only at sign-in")
	}
	// Switching it back on does not wake it: the route that saves the setting ends it.
	iw.org.wireAssetHandlerHooks(iw.org.assetHandler)
	iw.org.assetHandler.OnFrontEndsSwitchedOff("the-website", []string{"installed_app"})
	a.FrontEndsOff = nil
	_ = iw.org.assetHandler.Store.UpsertAsset(a)
	if roster.KeySpeaksFor(person, "", verkey) {
		t.Fatal("a grant woke when the owner switched the front end back on")
	}
}

func TestARemovedMembersGrantCannotWakeWhenTheyAreAddedAgain(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	iw.signedIn(t)
	person, _ := iw.org.browserKeys().Whose("the-website", iw.key, time.Now())
	iw.org.wireAssetHandlerHooks(iw.org.assetHandler)
	iw.org.assetHandler.OnMemberRemoved("the-website", person)
	if _, ok := iw.org.browserKeys().Whose("the-website", iw.key, time.Now()); ok {
		t.Fatal("a removed member's grant is still held")
	}
}

func TestAGrantOfADeletedAssetSpeaksForNoOne(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	iw.signedIn(t)
	person, _ := iw.org.browserKeys().Whose("the-website", iw.key, time.Now())
	if err := iw.org.assetHandler.Store.DeleteAsset("the-website"); err != nil {
		t.Fatal(err)
	}
	if (keysSpeakingAt{s: iw.org, asset: "the-website"}).KeySpeaksFor(person, "", aMachineVerkeyOf(t, iw.pub)) {
		t.Fatal("a deleted asset's grant still speaks")
	}
}

func TestTheOwnerCanListAndEndAGrant(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	iw.signedIn(t)
	router := chi.NewRouter()
	router.Get("/assets/{id}/app-key-grants", iw.org.handleListAppKeyGrants)
	router.Delete("/assets/{id}/app-key-grants/{key}", iw.org.handleEndAppKeyGrant)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest("GET", "/assets/the-website/app-key-grants", nil))
	var listed []appKeyGrantView
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || len(listed) != 1 || listed[0].Key != iw.key || listed[0].Platform != "android" {
		t.Fatalf("the owner does not see the grant: %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest("DELETE", "/assets/the-website/app-key-grants/"+iw.key, nil))
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if _, ok := iw.org.browserKeys().Whose("the-website", iw.key, time.Now()); ok {
		t.Fatal("the grant speaks after the owner ended it")
	}
}

func TestThePersonCanEndTheirOwnGrantAndNoOneElseCan(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	in, err := iw.start(anAppsRequest("the-website", nil), "the-website", iw.proof())
	if err != nil {
		t.Fatal(err)
	}
	person := aPersonsIdentityAgent(t)
	if _, err := person.Approve(login.StartLoginRequest{SessionToken: in.Session, RPSessionURL: iw.srv.URL}); err != nil {
		t.Fatal(err)
	}
	a, _, _ := iw.org.assetHandler.Store.GetAsset("the-website")
	endAs := func(who *login.Handler, key string) int {
		begin := httptest.NewRecorder()
		bb, _ := json.Marshal(map[string]string{"site_aid": a.PairwiseAID, "key": key})
		iw.org.handleBeginEndAppKey(begin, httptest.NewRequest("POST", "/x", bytes.NewReader(bb)))
		if begin.Code != 200 {
			t.Fatalf("begin: %d %s", begin.Code, begin.Body.String())
		}
		var ask map[string]string
		_ = json.Unmarshal(begin.Body.Bytes(), &ask)
		bundle := &login.ChallengeBundle{SiteAID: ask["site_aid"], Audience: ask["audience"], Nonce: ask["nonce"], BrowserKey: ask["browser_key"], FrontEnd: ask["front_end"]}
		rel, err := who.GetOrCreateRelationship(a.PairwiseAID, bundle)
		if err != nil {
			t.Fatal(err)
		}
		as, err := who.BuildAssertion(rel, bundle, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(as)
		rec := httptest.NewRecorder()
		iw.org.handleEndAppKey(rec, httptest.NewRequest("POST", "/x", bytes.NewReader(raw)))
		return rec.Code
	}
	// Another person, with a perfectly good assertion of their own, cannot end it.
	other, _, _ := theirAgent(t, 1000777)
	other.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	// The same root seed names relationships by their order, so the other
	// person's first is made elsewhere: their identifier at this app is their own.
	if _, err := other.GetOrCreateRelationship("DSomewhereElse", &login.ChallengeBundle{SiteAID: "DSomewhereElse"}); err != nil {
		t.Fatal(err)
	}
	if code := endAs(other, iw.key); code == 200 {
		t.Fatal("someone else ended the person's grant")
	}
	if _, ok := iw.org.browserKeys().Whose("the-website", iw.key, time.Now()); !ok {
		t.Fatal("the grant was ended by someone it is not for")
	}
	if code := endAs(person, iw.key); code != 200 {
		t.Fatalf("the person could not end their own grant: %d", code)
	}
	if _, ok := iw.org.browserKeys().Whose("the-website", iw.key, time.Now()); ok {
		t.Fatal("the grant speaks after the person ended it")
	}
}

func TestOnlyAnInstalledAppRecordMayHaveNoLapseTime(t *testing.T) {
	r := browserKeyRecord{FrontEnd: login.FrontEndBrowser}
	if r.liveAt(time.Now()) {
		t.Fatal("a browser record with no lapse time is forever")
	}
	r = browserKeyRecord{}
	if r.liveAt(time.Now()) {
		t.Fatal("a record of no kind with no lapse time is forever")
	}
	r = browserKeyRecord{FrontEnd: login.FrontEndInstalledApp}
	if !r.liveAt(time.Now()) {
		t.Fatal("an installed app's grant does not live without a lapse time")
	}
}

func TestTheConsentSaysAnInstalledAppsApprovalLastsUntilEnded(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	in, err := iw.start(anAppsRequest("the-website", nil), "the-website", iw.proof())
	if err != nil {
		t.Fatal(err)
	}
	p, err := aPersonsIdentityAgent(t).Preview(login.StartLoginRequest{SessionToken: in.Session, RPSessionURL: iw.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if p.FrontEnd != "installed_app" || !p.LastsUntilEnded {
		t.Fatalf("the consent does not say what is being approved: %+v", p)
	}
}

func aMachineVerkeyOf(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	v, err := iacrypto.MachineVerkeyForKey(elliptic.Marshal(elliptic.P256(), pub.X, pub.Y))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A route an add-on authenticates itself (an app's machine, sealed to this
// Identity Agent) names the app it found asking, and that app's own asset is
// the only one it may start a sign-in for.
func TestAnAddonsFoundCallerIsHeldToItsOwnAsset(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	plain := func(h map[string]string) *http.Request {
		r := httptest.NewRequest("POST", "/x", nil)
		for k, v := range h {
			r.Header.Set(k, v)
		}
		return r
	}
	start := func(r *http.Request, caller string) error {
		_, err := iw.org.startFrontEndKeySignIn(r, caller, "the-website", "https://portal.example", iw.key, "installed_app", iw.srv.URL, iw.proof())
		return err
	}
	if err := start(plain(nil), "the-website"); err != nil {
		t.Fatalf("the asset's own app, found by its add-on, was refused: %v", err)
	}
	if err := start(plain(nil), "some-other-app"); err == nil {
		t.Fatal("another app's caller started a sign-in for this asset")
	}
	if err := start(plain(nil), ""); err == nil {
		t.Fatal("a caller no one found started a sign-in")
	}
	if err := start(plain(map[string]string{"Origin": "https://evil.example"}), "the-website"); err == nil {
		t.Fatal("a page started an installed-app sign-in through an add-on's route")
	}
	if err := start(anAppsRequest("some-other-app", nil), "the-website"); err == nil {
		t.Fatal("the core's own check of who signed was overridden by the add-on's word")
	}
}
