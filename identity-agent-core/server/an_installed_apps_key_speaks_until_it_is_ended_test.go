package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/agentmessage"
	"identity-agent-core/asset"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"
	"identity-agent-core/trail"
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
	priv *ecdsa.PrivateKey
	// asked is the challenge of the latest ask the core issued: what the
	// stand-in hardware checks it was asked to attest with.
	asked []byte
	said  *secureenclave.InstalledAppKeyFacts // what the stand-in hardware says
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
	iw := &anInstalledAppWorld{aWebsiteWorld: w, key: tp, pub: &k.PublicKey, priv: k}
	signer := bytes.Repeat([]byte{0xab}, 32)
	iw.said = &secureenclave.InstalledAppKeyFacts{Public: &k.PublicKey, Platform: "android", Level: "strongbox",
		AppPackages: []string{theAndroidPackage}, AppSigners: [][]byte{signer}, AppIDPresent: true}
	stand := func(wantPlatform string) {
		fake := func(ev, ch []byte, now time.Time) (*secureenclave.InstalledAppKeyFacts, error) {
			if !bytes.Equal(ch, iw.asked) {
				return nil, errors.New("not the challenge the core issued")
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
		verifyTPMInstalledKey = func(ev, ch, credKey []byte, now time.Time) (*secureenclave.InstalledAppKeyFacts, error) {
			if len(credKey) < secureenclave.TPMCredentialKeyLen || bytes.Equal(credKey, ch) {
				return nil, errors.New("no secret credential key from the core")
			}
			return fake(ev, ch, now)
		}
	}
	oa, oap, ot := verifyAndroidInstalledKey, verifyAppleInstalledKey, verifyTPMInstalledKey
	t.Cleanup(func() { verifyAndroidInstalledKey, verifyAppleInstalledKey, verifyTPMInstalledKey = oa, oap, ot })
	stand("")
	return iw
}

// proof is what the app's back end carries from its installed front end: the
// ask the core issued, the stand-in hardware's evidence, and the key's own
// signature over the sign-in statement for that ask.
func (iw *anInstalledAppWorld) proof() *InstalledAppKeyProof {
	return iw.proofFor("the-website", iw.priv)
}

func (iw *anInstalledAppWorld) proofFor(assetID string, signer *ecdsa.PrivateKey) *InstalledAppKeyProof {
	ask, err := iw.org.beginInstalledAppKey(anAppsRequest(assetID, nil), "", assetID)
	if err != nil {
		panic(err)
	}
	iw.asked = ask.Challenge
	return &InstalledAppKeyProof{Platform: iw.said.Platform, Evidence: []byte("evidence"), Ask: ask.ID,
		KeySignature: iw.signs(signer, assetID, ask.Challenge, iw.key)}
}

// signs is the key's signature over the statement: ECDSA, or on Apple the
// App Attest assertion, made the way Apple's steps say.
func (iw *anInstalledAppWorld) signs(k *ecdsa.PrivateKey, assetID string, challenge []byte, thumbprint string) []byte {
	digest := sha256.Sum256(InstalledAppSignInStatement(assetID, challenge, thumbprint))
	if iw.said.Platform == "apple" {
		return anAppAttestAssertion(k, "TEAM123456.org.example.portal", 3, digest[:])
	}
	sig, _ := ecdsa.SignASN1(rand.Reader, k, digest[:])
	return sig
}

// anAppAttestAssertion is an assertion over clientDataHash by a software key
// standing in for the Secure Enclave's: CBOR {signature, authenticatorData}.
func anAppAttestAssertion(k *ecdsa.PrivateKey, appID string, counter uint32, clientDataHash []byte) []byte {
	rp := sha256.Sum256([]byte(appID))
	authData := append(append([]byte{}, rp[:]...), 0, byte(counter>>24), byte(counter>>16), byte(counter>>8), byte(counter))
	nonce := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash...))
	digest := sha256.Sum256(nonce[:])
	sig, _ := ecdsa.SignASN1(rand.Reader, k, digest[:])
	head := func(major byte, n int) []byte {
		if n < 24 {
			return []byte{major<<5 | byte(n)}
		}
		return []byte{major<<5 | 24, byte(n)}
	}
	out := head(5, 2)
	for _, kv := range []struct {
		k string
		v []byte
	}{{"signature", sig}, {"authenticatorData", authData}} {
		out = append(out, head(3, len(kv.k))...)
		out = append(out, kv.k...)
		out = append(out, head(2, len(kv.v))...) // a byte string over 255 would need the long form: neither is
		out = append(out, kv.v...)
	}
	return out
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
// the core's own, made before any sign-in exists. Each proof is built inside
// its subtest, after mod() has said what the stand-in hardware attests, so the
// one thing wrong in a case is the only thing wrong with it, and each case is
// held to its own reason: a guard removed turns its case into a different
// refusal, or a sign-in, and fails.
func TestAnInstalledAppSignInRestsOnProofAndNotOnTheCallersWord(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	app := func() *http.Request { return anAppsRequest("the-website", nil) }
	good := func() *InstalledAppKeyProof { return iw.proof() }
	for name, c := range map[string]struct {
		req   func() *http.Request
		asset string
		proof func() *InstalledAppKeyProof
		mod   func()
		why   string // what the refusal says
	}{
		"no proof":       {req: app, asset: "the-website", why: "needs a hardware attestation"},
		"empty evidence": {req: app, asset: "the-website", proof: func() *InstalledAppKeyProof { return &InstalledAppKeyProof{Platform: "android"} }, why: "needs a hardware attestation"},
		"a request no app signed": {req: func() *http.Request { return httptest.NewRequest("POST", "/x", nil) }, asset: "the-website", proof: good,
			why: "only an app's back end"},
		"another app's asset": {req: func() *http.Request { return anAppsRequest("some-other-app", nil) }, asset: "the-website", proof: good,
			why: "its own asset only"},
		"a page, by Origin": {req: func() *http.Request {
			return anAppsRequest("the-website", map[string]string{"Origin": "https://evil.example"})
		}, asset: "the-website", proof: good,
			why: "web page"},
		"a page, by Fetch Metadata": {req: func() *http.Request { return anAppsRequest("the-website", map[string]string{"Sec-Fetch-Mode": "cors"}) }, asset: "the-website", proof: good,
			why: "web page"},
		"an unknown platform": {req: app, asset: "the-website", proof: func() *InstalledAppKeyProof {
			p := good()
			p.Platform = "toaster"
			return p
		}, why: "not 'toaster'"},
		"another key than the attested": {req: app, asset: "the-website", proof: good, mod: func() { iw.said.Public = &other.PublicKey },
			why: "attested key is not the key"},
		"another package": {req: app, asset: "the-website", proof: good, mod: func() { iw.said.AppPackages = []string{"org.evil"} },
			why: "not made by the program the owner named"},
		"no program stated, though a package is": {req: app, asset: "the-website", proof: good, mod: func() { iw.said.AppIDPresent = false },
			why: "not made by the program the owner named"},
		"no package stated": {req: app, asset: "the-website", proof: good, mod: func() { iw.said.AppPackages = nil },
			why: "not made by the program the owner named"},
		"another signing certificate": {req: app, asset: "the-website", proof: good, mod: func() { iw.said.AppSigners = [][]byte{bytes.Repeat([]byte{1}, 32)} },
			why: "certificate the owner did not name"},
		"one certificate of two is not the owner's": {req: app, asset: "the-website", proof: good,
			mod: func() { iw.said.AppSigners = [][]byte{bytes.Repeat([]byte{0xab}, 32), bytes.Repeat([]byte{1}, 32)} },
			why: "certificate the owner did not name"},
		"no signing certificate stated": {req: app, asset: "the-website", proof: good, mod: func() { iw.said.AppSigners = nil },
			why: "names no signing certificate"},
		"a TPM key the owner did not accept": {req: app, asset: "the-website", proof: good, mod: func() { iw.said.Platform = "tpm" },
			why: "not accepted a TPM key"},
		"a platform that vouches as another": {req: app, asset: "the-website", proof: func() *InstalledAppKeyProof {
			p := good()
			p.Platform = "apple" // the stand-in attests android
			return p
		}, why: "not proved by the platform it names"},
	} {
		t.Run(name, func(t *testing.T) {
			saved := *iw.said
			defer func() { *iw.said = saved }()
			if c.mod != nil {
				c.mod()
			}
			var p *InstalledAppKeyProof
			if c.proof != nil {
				p = c.proof() // built now, after mod, so it is fresh and signs what is attested
			}
			_, err := iw.start(c.req(), c.asset, p)
			var refused *SignInRefused
			if !errors.As(err, &refused) {
				t.Fatalf("started: %v", err)
			}
			if !strings.Contains(refused.Reason, c.why) {
				t.Fatalf("refused for the wrong reason: %q, want it to say %q", refused.Reason, c.why)
			}
		})
	}
	// The same proof, with nothing wrong, starts: the cases above fail for their one fault.
	if _, err := iw.start(app(), "the-website", good()); err != nil {
		t.Fatalf("a proof with nothing wrong was refused: %v", err)
	}
	// An owner who named nothing accepts no installed-app key at all.
	a, _, _ := iw.org.assetHandler.Store.GetAsset("the-website")
	a.InstalledApp = asset.InstalledAppIdentity{}
	_ = iw.org.assetHandler.Store.UpsertAsset(a)
	if _, err := iw.start(app(), "the-website", good()); err == nil || !strings.Contains(err.Error(), "has not said which installed program") {
		t.Fatalf("an installed-app key was accepted for an app whose owner named no program: %v", err)
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

// An attestation is fresh: the core asks for it once, and the key itself signs
// each sign-in. A leaked attestation holds only public facts.
func TestAnInstalledAppsAttestationIsFreshAndItsKeySignsEachSignIn(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	startWith := func(p *InstalledAppKeyProof) error {
		_, err := iw.start(anAppsRequest("the-website", nil), "the-website", p)
		return err
	}

	// The same proof is not accepted twice: the ask is spent when it is read.
	p := iw.proof()
	if err := startWith(p); err != nil {
		t.Fatal(err)
	}
	if err := startWith(p); err == nil {
		t.Fatal("a proof was accepted a second time, so a leaked attestation could be shown again")
	}

	// Evidence anyone could hold is not enough: the key must sign this sign-in.
	forged := iw.proofFor("the-website", other) // someone else's key signs
	if err := startWith(forged); err == nil {
		t.Fatal("a sign-in naming the key was started by someone who does not hold it")
	}
	unsigned := iw.proof()
	unsigned.KeySignature = nil
	if err := startWith(unsigned); err == nil {
		t.Fatal("a sign-in the key did not sign was started")
	}
	first := iw.proof()
	firstAsked := iw.asked
	second := iw.proof()
	first.KeySignature = second.KeySignature // the signature of another ask
	iw.asked = firstAsked
	if err := startWith(first); err == nil {
		t.Fatal("a signature made for another ask opened this one")
	}
	named := iw.proof()
	named.KeySignature = iw.signs(iw.priv, "the-website", iw.asked, "another-key-thumbprint")
	if err := startWith(named); err == nil {
		t.Fatal("a signature over another key's name opened this one")
	}

	// An ask the core did not issue, or that has expired, is refused.
	bad := iw.proof()
	bad.Ask = "not-an-ask"
	if err := startWith(bad); err == nil {
		t.Fatal("an ask the core never issued was accepted")
	}
	old := iw.proof()
	iw.org.installedAppAskMu.Lock()
	a := iw.org.installedAppAsks[old.Ask]
	a.until = time.Now().Add(-time.Second)
	iw.org.installedAppAsks[old.Ask] = a
	iw.org.installedAppAskMu.Unlock()
	if err := startWith(old); err == nil {
		t.Fatal("an expired ask was accepted")
	}

	// An ask another app was issued is not this app's.
	theirs, err := iw.org.beginInstalledAppKey(anAppsRequest("some-other-app", nil), "", "some-other-app")
	if err != nil {
		t.Fatal(err)
	}
	borrowed := iw.proof()
	borrowed.Ask = theirs.ID
	borrowed.KeySignature = iw.signs(iw.priv, "the-website", theirs.Challenge, iw.key) // everything else is right
	iw.asked = theirs.Challenge
	if err := startWith(borrowed); err == nil {
		t.Fatal("another app's ask was used for this asset")
	}

	// A page cannot ask, and an app cannot hold unbounded asks open.
	if _, err := iw.org.beginInstalledAppKey(anAppsRequest("the-website", map[string]string{"Origin": "https://evil.example"}), "", "the-website"); err == nil {
		t.Fatal("a web page was given an ask")
	}
	if _, err := iw.org.beginInstalledAppKey(anAppsRequest("some-other-app", nil), "", "the-website"); err == nil {
		t.Fatal("another app was given an ask for this asset")
	}
	var last error
	for i := 0; i < installedAppAsksPerAsset+1; i++ {
		_, last = iw.org.beginInstalledAppKey(anAppsRequest("the-website", nil), "", "the-website")
	}
	if last == nil {
		t.Fatal("an app held more asks open than the cap")
	}
}

// A TPM's credential is keyed by a secret only the core holds: what the
// verifier is given is not the challenge the app holds.
func TestATPMSignInIsGivenTheCoresSecretCredentialKey(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	a, _, _ := iw.org.assetHandler.Store.GetAsset("the-website")
	a.InstalledApp.TPMKeys = true
	_ = iw.org.assetHandler.Store.UpsertAsset(a)
	iw.said.Platform = "tpm"
	var gotChallenge, gotKey []byte
	inner := verifyTPMInstalledKey
	verifyTPMInstalledKey = func(ev, ch, credKey []byte, now time.Time) (*secureenclave.InstalledAppKeyFacts, error) {
		gotChallenge, gotKey = ch, credKey
		return inner(ev, ch, credKey, now)
	}
	p := iw.proof()
	if _, err := iw.start(anAppsRequest("the-website", nil), "the-website", p); err != nil {
		t.Fatal(err)
	}
	if len(gotKey) < secureenclave.TPMCredentialKeyLen || bytes.Equal(gotKey, gotChallenge) || bytes.Equal(gotKey, iw.asked) {
		t.Fatal("the TPM check was not given a secret key of the core's own")
	}
	// What the app was told is the challenge and the ask's name, nothing else.
	ask, _ := iw.org.beginInstalledAppKey(anAppsRequest("the-website", nil), "", "the-website")
	raw, _ := json.Marshal(ask)
	if bytes.Contains(raw, []byte("credential")) {
		t.Fatalf("the ask hands the app something about the credential key: %s", raw)
	}
}

// A live app-key grant is never replaced by a different person's sign-in.
func TestALiveAppKeyGrantIsNotReplacedByAnotherPerson(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	iw.signedIn(t)
	owner, _ := iw.org.browserKeys().Whose("the-website", iw.key, time.Now())
	fact := installedAppFact{Platform: "android", Level: "tee", Proved: time.Now()}

	if err := iw.org.browserKeys().RecordAppKey("the-website", "Esomeone-else", iw.key, time.Now(), nil, fact); !errors.Is(err, errGrantHeld) {
		t.Fatalf("another person replaced a live grant: %v", err)
	}
	if now, _ := iw.org.browserKeys().Whose("the-website", iw.key, time.Now()); now != owner {
		t.Fatalf("the grant now speaks for %q, not %q", now, owner)
	}
	// The same person signing in again refreshes it, and once it ends the key may speak for someone else.
	if err := iw.org.browserKeys().RecordAppKey("the-website", owner, iw.key, time.Now(), nil, fact); err != nil {
		t.Fatalf("the person could not sign in again: %v", err)
	}
	if _, err := iw.org.browserKeys().End("the-website", iw.key, ""); err != nil {
		t.Fatal(err)
	}
	if err := iw.org.browserKeys().RecordAppKey("the-website", "Esomeone-else", iw.key, time.Now(), nil, fact); err != nil {
		t.Fatalf("an ended grant still held the key: %v", err)
	}
}

// An Apple App Attest key signs only assertions, so a statement it signs is
// read as one: an assertion over the statement's hash is the person's, a plain
// signature and an assertion over other words are not.
func TestAnAppleAppAttestKeySpeaksForThePersonByAnAssertion(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	iw.said.Platform = "apple"
	iw.signedIn(t)
	person, _ := iw.org.browserKeys().Whose("the-website", iw.key, time.Now())
	roster := keysSpeakingAt{s: iw.org, asset: "the-website"}
	id, err := iacrypto.MachineAIDForKey(elliptic.Marshal(elliptic.P256(), iw.pub.X, iw.pub.Y))
	if err != nil {
		t.Fatal(err)
	}
	verkey := aMachineVerkeyOf(t, iw.pub)
	st := agentmessage.PersonStatement{
		Agent: iw.org.thisIdentityAgentsIdentifier(), Conversation: "c1", MessageID: "m1",
		Kind: agentmessage.PersonKindMessage, From: person, Signer: id, To: "Eagent1",
		Nonce: "nonce-0123456789abcdefm1", Time: time.Now().UTC().Format(time.RFC3339),
		FingerprintVersion: agentmessage.FingerprintV1, Fingerprint: "AAAA",
	}
	hash := sha256.Sum256(st.Bytes())
	assert := func(h [32]byte) string {
		return base64.RawURLEncoding.EncodeToString(anAppAttestAssertion(iw.priv, "TEAM123456.org.example.portal", 9, h[:]))
	}
	check := func(sig string, mutate func(*agentmessage.PersonStatement)) error {
		s := st
		if mutate != nil {
			mutate(&s)
		}
		return trail.CheckAuthor(trail.Write{Statement: s, Verkey: verkey, Signature: sig}, st.Agent, roster)
	}
	if err := check(assert(hash), nil); err != nil {
		t.Fatalf("an App Attest assertion over the statement was refused: %v", err)
	}
	plain, _ := ecdsa.SignASN1(rand.Reader, iw.priv, hash[:])
	if err := check(base64.RawURLEncoding.EncodeToString(plain), nil); err == nil {
		t.Fatal("a plain signature was read as an Apple key's statement")
	}
	other := sha256.Sum256([]byte("other words"))
	if err := check(assert(other), nil); err == nil {
		t.Fatal("an assertion over other words was accepted")
	}
	if err := check(assert(hash), func(s *agentmessage.PersonStatement) { s.MessageID = "m2" }); err == nil {
		t.Fatal("an assertion was accepted for a statement it did not sign")
	}
	// The signer's identifier and the key it comes with must be one key: a valid
	// assertion by this key under another machine's identifier is not that machine's.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherID, err := iacrypto.MachineAIDForKey(elliptic.Marshal(elliptic.P256(), otherKey.PublicKey.X, otherKey.PublicKey.Y))
	if err != nil {
		t.Fatal(err)
	}
	if err := check(assert(hash), func(s *agentmessage.PersonStatement) { s.Signer = otherID }); err == nil || !strings.Contains(err.Error(), "not the same key") {
		t.Fatalf("a signer's identifier that is not its key was accepted: %v", err)
	}
	// The owner's program is the one asked on every use.
	as, _, _ := iw.org.assetHandler.Store.GetAsset("the-website")
	as.InstalledApp.AppleAppID = "TEAM123456.org.evil"
	_ = iw.org.assetHandler.Store.UpsertAsset(as)
	if err := check(assert(hash), nil); err == nil {
		t.Fatal("an assertion for a program the owner no longer names was accepted")
	}
}

// The public begin route is capped by caller, so one caller cannot stop the others ending grants.
func TestOneCallerCannotFillTheNoncesThatEndGrants(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	a, _, _ := iw.org.assetHandler.Store.GetAsset("the-website")
	endAppKeyMu.Lock()
	endAppKeyAsked = map[string]endAppKeyAsk{}
	endAppKeyMu.Unlock()
	t.Cleanup(func() { endAppKeyMu.Lock(); endAppKeyAsked = map[string]endAppKeyAsk{}; endAppKeyMu.Unlock() })
	begin := func(from string) int {
		bb, _ := json.Marshal(map[string]string{"site_aid": a.PairwiseAID, "key": iw.key})
		r := httptest.NewRequest("POST", "/x", bytes.NewReader(bb))
		r.RemoteAddr = from + ":4000"
		rec := httptest.NewRecorder()
		iw.org.handleBeginEndAppKey(rec, r)
		return rec.Code
	}
	for i := 0; i < endAppKeyPerCaller; i++ {
		if code := begin("192.0.2.1"); code != 200 {
			t.Fatalf("nonce %d: %d", i, code)
		}
	}
	if code := begin("192.0.2.1"); code != http.StatusTooManyRequests {
		t.Fatalf("a caller was not capped: %d", code)
	}
	if code := begin("192.0.2.2"); code != 200 {
		t.Fatalf("another caller was stopped by the first: %d", code)
	}
	// Nonces expire: once they have, the first caller may ask again.
	endAppKeyMu.Lock()
	for n, k := range endAppKeyAsked {
		k.until = time.Now().Add(-time.Second)
		endAppKeyAsked[n] = k
	}
	endAppKeyMu.Unlock()
	if code := begin("192.0.2.1"); code != 200 {
		t.Fatalf("expired nonces still counted against the caller: %d", code)
	}
}

// The callback keeps an installed app's grant only for a sign-in the core
// itself proved the key for. One the core holds no proof for (the process
// restarted since it started) is refused and nothing is kept.
func TestACallbackWithNoProofHeldKeepsNoAppKeyGrant(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	in, err := iw.start(anAppsRequest("the-website", nil), "the-website", iw.proof())
	if err != nil {
		t.Fatal(err)
	}
	if _, held := iw.org.takeInstalledAppFact(in.Session); !held {
		t.Fatal("the core held no proof for a sign-in it started")
	}
	if _, err := aPersonsIdentityAgent(t).Approve(login.StartLoginRequest{SessionToken: in.Session, RPSessionURL: iw.srv.URL}); err == nil {
		t.Fatal("an installed-app sign-in with no proof held was approved")
	}
	if _, ok := iw.org.browserKeys().Whose("the-website", iw.key, time.Now()); ok {
		t.Fatal("a grant was kept for a key the core held no proof for")
	}
	if grants := iw.org.browserKeys().AppKeyGrants("the-website", time.Now()); len(grants) != 0 {
		t.Fatalf("grants held: %+v", grants)
	}
}

// Removing a member through the route the owner uses ends their grant: the
// handler itself is called, not the hook it calls.
func TestRemovingAMemberThroughTheRouteEndsTheirGrant(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	iw.signedIn(t)
	person, _ := iw.org.browserKeys().Whose("the-website", iw.key, time.Now())
	iw.org.wireAssetHandlerHooks(iw.org.assetHandler)
	router := chi.NewRouter()
	router.Delete("/assets/{id}/members/{aid}", iw.org.assetHandler.HandleRemoveMember)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest("DELETE", "/assets/the-website/members/"+person, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if _, ok := iw.org.browserKeys().Whose("the-website", iw.key, time.Now()); ok {
		t.Fatal("a removed member's grant is still held after the owner removed them")
	}
}

// An Apple key proves it holds the key by an assertion over the sign-in
// statement, made for the owner's program: a plain signature, one by another
// key, one over other words and one for another program are each refused.
func TestAnAppleInstalledAppKeyIsHeldToAnAssertionAtSignIn(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	iw.said.Platform = "apple"
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, sign := range map[string]func(ask []byte) []byte{
		"a plain signature": func(ask []byte) []byte {
			d := sha256.Sum256(InstalledAppSignInStatement("the-website", ask, iw.key))
			sig, _ := ecdsa.SignASN1(rand.Reader, iw.priv, d[:])
			return sig
		},
		"an assertion by another key": func(ask []byte) []byte {
			d := sha256.Sum256(InstalledAppSignInStatement("the-website", ask, iw.key))
			return anAppAttestAssertion(other, "TEAM123456.org.example.portal", 3, d[:])
		},
		"an assertion over other words": func(ask []byte) []byte {
			d := sha256.Sum256([]byte("other words"))
			return anAppAttestAssertion(iw.priv, "TEAM123456.org.example.portal", 3, d[:])
		},
		"an assertion for another program": func(ask []byte) []byte {
			d := sha256.Sum256(InstalledAppSignInStatement("the-website", ask, iw.key))
			return anAppAttestAssertion(iw.priv, "TEAM123456.org.evil", 3, d[:])
		},
		"no signature": func([]byte) []byte { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			p := iw.proof()
			p.KeySignature = sign(iw.asked)
			_, err := iw.start(anAppsRequest("the-website", nil), "the-website", p)
			var refused *SignInRefused
			if !errors.As(err, &refused) || !strings.Contains(refused.Reason, "did not sign this sign-in") {
				t.Fatalf("an Apple key's sign-in with %s was not refused for it: %v", name, err)
			}
		})
	}
	if _, err := iw.start(anAppsRequest("the-website", nil), "the-website", iw.proof()); err != nil {
		t.Fatalf("a proper assertion was refused: %v", err)
	}
}

// Behind a trusted proxy every request reaches the core from the proxy's own
// address, so the per-caller cap counts the visitor the proxy names, not the proxy.
func TestTheEndNonceCapCountsTheVisitorBehindAProxyNotTheProxy(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "10.0.0.1")
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	a, _, _ := iw.org.assetHandler.Store.GetAsset("the-website")
	endAppKeyMu.Lock()
	endAppKeyAsked = map[string]endAppKeyAsk{}
	endAppKeyMu.Unlock()
	t.Cleanup(func() { endAppKeyMu.Lock(); endAppKeyAsked = map[string]endAppKeyAsk{}; endAppKeyMu.Unlock() })
	begin := func(visitor string) int {
		bb, _ := json.Marshal(map[string]string{"site_aid": a.PairwiseAID, "key": iw.key})
		r := httptest.NewRequest("POST", "/x", bytes.NewReader(bb))
		r.RemoteAddr = "10.0.0.1:4000"
		r.Header.Set("X-Forwarded-For", visitor)
		rec := httptest.NewRecorder()
		iw.org.handleBeginEndAppKey(rec, r)
		return rec.Code
	}
	for i := 0; i < endAppKeyPerCaller; i++ {
		if code := begin("198.51.100.7"); code != 200 {
			t.Fatalf("nonce %d: %d", i, code)
		}
	}
	if code := begin("198.51.100.7"); code != http.StatusTooManyRequests {
		t.Fatalf("a visitor behind the proxy was not capped: %d", code)
	}
	if code := begin("198.51.100.8"); code != 200 {
		t.Fatalf("one visitor behind the proxy stopped another: %d", code)
	}
}

// The person's own Identity Agent keeps what they approved, lists it, and ends
// it with the signed end the app's host already takes.
func TestThePersonsIdentityAgentListsAnInstalledAppTheyApprovedAndEndsIt(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	in, err := iw.start(anAppsRequest("the-website", nil), "the-website", iw.proof())
	if err != nil {
		t.Fatal(err)
	}
	person := aPersonsIdentityAgent(t)
	list := func() []login.InstalledAppSignIn {
		rec := httptest.NewRecorder()
		person.HandleInstalledAppSignIns(rec, httptest.NewRequest("GET", "/x", nil))
		var out struct {
			L []login.InstalledAppSignIn `json:"installed_app_sign_ins"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out.L
	}
	if len(list()) != 0 {
		t.Fatal("the list holds something never approved")
	}
	if _, err := person.Approve(login.StartLoginRequest{SessionToken: in.Session, RPSessionURL: iw.srv.URL}); err != nil {
		t.Fatal(err)
	}
	got := list()
	if len(got) != 1 || got[0].Key != iw.key {
		t.Fatalf("the approved sign-in is not listed: %+v", got)
	}
	if _, ok := iw.org.browserKeys().Whose("the-website", iw.key, time.Now()); !ok {
		t.Fatal("the grant is not live before it is ended")
	}
	body, _ := json.Marshal(map[string]string{"site_aid": got[0].SiteAID, "key": got[0].Key})
	rec := httptest.NewRecorder()
	person.HandleEndInstalledAppSignIn(rec, httptest.NewRequest("POST", "/x", bytes.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("ending it: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := iw.org.browserKeys().Whose("the-website", iw.key, time.Now()); ok {
		t.Fatal("the grant still speaks after the person ended it from their list")
	}
	if len(list()) != 0 {
		t.Fatal("an ended sign-in is still listed")
	}
	// A key the person never approved is refused, not forwarded.
	rec = httptest.NewRecorder()
	person.HandleEndInstalledAppSignIn(rec, httptest.NewRequest("POST", "/x", bytes.NewReader(body)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("ending a sign-in not on the list answered %d", rec.Code)
	}
}
