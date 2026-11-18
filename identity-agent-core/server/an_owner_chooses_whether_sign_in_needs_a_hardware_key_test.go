package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/asset"
	"identity-agent-core/login"
)

// Whether an installed front end must sign in with a hardware key is its owner's
// word, per utility app, and off unless they turn it on (ADR-072 Amendment 17).
// Off, a key held in software signs in at the lower grade; on, it is refused,
// and the caller has no way to pick the weaker path.

// aSoftwareKey is an installed front end's key held in software.
type aSoftwareKey struct {
	priv *ecdsa.PrivateKey
	tp   string
}

func newSoftwareKey(t *testing.T) aSoftwareKey {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tp, err := thumbprintOfECKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return aSoftwareKey{priv: k, tp: tp}
}

// softwareProof is what an installed front end with a key in software sends: the
// ask the core issued, the key's point, and the key's signature over the sign-in
// statement for that ask. Nothing vouches for where the key is kept.
func (k aSoftwareKey) softwareProof(t *testing.T, iw *anInstalledAppWorld) *InstalledAppKeyProof {
	t.Helper()
	ask, err := iw.org.beginInstalledAppKey(anAppsRequest("the-website", nil), "", "the-website")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(InstalledAppSignInStatement("the-website", ask.Challenge, k.tp))
	sig, _ := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	return &InstalledAppKeyProof{Platform: PlatformSoftware, Evidence: elliptic.Marshal(elliptic.P256(), k.priv.X, k.priv.Y), Ask: ask.ID, KeySignature: sig}
}

func (k aSoftwareKey) start(iw *anInstalledAppWorld, p *InstalledAppKeyProof) (BrowserKeySignIn, error) {
	return iw.org.startFrontEndKeySignIn(anAppsRequest("the-website", nil), "", "the-website", "https://portal.example", k.tp, "installed_app", iw.srv.URL, p)
}

func ownerRequiresHardware(t *testing.T, iw *anInstalledAppWorld, require bool) {
	t.Helper()
	iw.org.wireAssetHandlerHooks(iw.org.assetHandler)
	if _, err := iw.org.assetHandler.SetRequireHardwareKey("the-website", require); err != nil {
		t.Fatal(err)
	}
}

func approve(t *testing.T, iw *anInstalledAppWorld, in BrowserKeySignIn) error {
	t.Helper()
	_, err := aPersonsIdentityAgent(t).Approve(login.StartLoginRequest{SessionToken: in.Session, RPSessionURL: iw.srv.URL})
	return err
}

func TestAnAppThatRequiresAHardwareKeyRefusesAKeyHeldInSoftware(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	ownerRequiresHardware(t, iw, true)
	k := newSoftwareKey(t)
	_, err := k.start(iw, k.softwareProof(t, iw))
	if err == nil {
		t.Fatal("an app whose owner requires a hardware key let a key held in software sign in")
	}
	if err.Error() != errHardwareKeyRequired.Error() {
		t.Fatalf("the refusal does not tell the person what the owner requires: %v", err)
	}
	// A key the hardware proves still signs in.
	iw.signedIn(t)
	if g := iw.org.browserKeys().AppKeyGrants("the-website", time.Now()); len(g) != 1 || g[0].Grade() != KeyGradeHardware {
		t.Fatalf("a hardware key's sign-in was not kept at the hardware grade: %+v", g)
	}
}

func TestAnAppThatDoesNotRequireOneAcceptsAKeyHeldInSoftwareAtTheLowerGrade(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	k := newSoftwareKey(t)
	in, err := k.start(iw, k.softwareProof(t, iw))
	if err != nil {
		t.Fatalf("the default refused a key held in software: %v", err)
	}
	if err := approve(t, iw, in); err != nil {
		t.Fatal(err)
	}
	res, err := iw.org.browserKeySignInResult(siteOf(iw.org, in.Session), in.Session, in.Collector)
	if err != nil || res.State != "verified" || res.FrontEnd != "installed_app" || res.KeyGrade != KeyGradeSoftware {
		t.Fatalf("the app's back end is not told the sign-in is at the software grade: %+v %v", res, err)
	}
	rec, ok := iw.org.browserKeys().Get("the-website", k.tp, time.Now())
	if !ok || rec.Grade() != KeyGradeSoftware {
		t.Fatalf("the grant was not kept at the software grade: %+v", rec)
	}
	// It lapses as a browser's does, at the owner's sign-in lifetime.
	if want := time.Now().Add(asset.DefaultSignInLifetime); rec.Until.IsZero() || rec.Until.After(want.Add(time.Minute)) || rec.Until.Before(want.Add(-time.Minute)) {
		t.Fatalf("a key held in software was given %v, not the sign-in lifetime", rec.Until)
	}
	if _, ok := iw.org.browserKeys().Get("the-website", k.tp, time.Now().Add(asset.DefaultSignInLifetime+time.Minute)); ok {
		t.Fatal("a key held in software speaks past its lifetime")
	}
	if until, ok, _ := iw.org.browserKeySpeaksUntil("the-website", rec.Person, k.tp); !ok || until.IsZero() {
		t.Fatal("the back end is not told when a key held in software stops speaking")
	}
	// The owner sees the grade beside the grant.
	router := chi.NewRouter()
	router.Get("/assets/{id}/app-key-grants", iw.org.handleListAppKeyGrants)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/assets/the-website/app-key-grants", nil))
	var listed []appKeyGrantView
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil || len(listed) != 1 || listed[0].Grade != KeyGradeSoftware || listed[0].Until == nil {
		t.Fatalf("the owner does not see the grant's grade: %s", w.Body.String())
	}
	// And a hardware key's sign-in says hardware.
	hw, err := iw.start(anAppsRequest("the-website", nil), "the-website", iw.proof())
	if err != nil {
		t.Fatal(err)
	}
	if err := approve(t, iw, hw); err != nil {
		t.Fatal(err)
	}
	if res, err := iw.org.browserKeySignInResult(siteOf(iw.org, hw.Session), hw.Session, hw.Collector); err != nil || res.KeyGrade != KeyGradeHardware {
		t.Fatalf("a hardware key's sign-in is not told as hardware: %+v %v", res, err)
	}
}

// The client has no way to the weaker path once the owner requires a hardware
// key: not by naming the software platform, not by a sign-in it started before
// the owner said so, and not by a grant it already holds.
func TestTheCallerCannotPickTheWeakerPathWhenAHardwareKeyIsRequired(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	k := newSoftwareKey(t)

	// Each of these is refused even where software is allowed, so the software
	// path is no looser than the hardware one in what it checks.
	t.Run("a key in software that did not sign the sign-in", func(t *testing.T) {
		p := k.softwareProof(t, iw)
		other := newSoftwareKey(t)
		p.KeySignature = other.softwareProof(t, iw).KeySignature
		if _, err := k.start(iw, p); err == nil {
			t.Fatal("a sign-in the key did not sign was started")
		}
	})
	t.Run("a point that is not the key named", func(t *testing.T) {
		p := k.softwareProof(t, iw)
		other := newSoftwareKey(t)
		p.Evidence = elliptic.Marshal(elliptic.P256(), other.priv.X, other.priv.Y)
		if _, err := k.start(iw, p); err == nil || !strings.Contains(err.Error(), "not the key this sign-in names") {
			t.Fatalf("a point for another key was taken: %v", err)
		}
	})
	t.Run("an ask used twice", func(t *testing.T) {
		p := k.softwareProof(t, iw)
		if _, err := k.start(iw, p); err != nil {
			t.Fatal(err)
		}
		if _, err := k.start(iw, p); err == nil {
			t.Fatal("an ask was used twice")
		}
	})

	// A sign-in started while software was allowed, approved after the owner
	// required a hardware key, is not kept.
	pending, err := k.start(iw, k.softwareProof(t, iw))
	if err != nil {
		t.Fatal(err)
	}
	// A grant a key in software already holds.
	held := newSoftwareKey(t)
	in, err := held.start(iw, held.softwareProof(t, iw))
	if err != nil {
		t.Fatal(err)
	}
	if err := approve(t, iw, in); err != nil {
		t.Fatal(err)
	}
	person, ok := iw.org.browserKeys().Whose("the-website", held.tp, time.Now())
	if !ok || !iw.org.appKeyStillSpeaks("the-website", held.tp, person) {
		t.Fatal("a key in software did not speak while software was allowed")
	}
	// A hardware key's grant, which the owner's requirement leaves alone.
	iw.signedIn(t)

	ownerRequiresHardware(t, iw, true)

	if _, err := k.start(iw, k.softwareProof(t, iw)); err == nil {
		t.Fatal("naming the software platform got round the owner's requirement")
	}
	if err := approve(t, iw, pending); err == nil {
		t.Fatal("a software sign-in started before the owner required a hardware key was approved after it")
	}
	if _, ok := iw.org.browserKeys().Get("the-website", k.tp, time.Now()); ok {
		t.Fatal("a software sign-in approved after the owner required a hardware key was kept")
	}
	if iw.org.appKeyStillSpeaks("the-website", held.tp, person) {
		t.Fatal("a key in software kept speaking after the owner required a hardware key")
	}
	if _, ok := iw.org.browserKeys().Get("the-website", held.tp, time.Now()); ok {
		t.Fatal("a key in software's grant was not ended when the owner required a hardware key, so turning it off again would wake it")
	}
	hwPerson, ok := iw.org.browserKeys().Whose("the-website", iw.key, time.Now())
	if !ok || !iw.org.appKeyStillSpeaks("the-website", iw.key, hwPerson) {
		t.Fatal("requiring a hardware key ended a grant the hardware proved")
	}

	// A grant stored at the software grade is refused on use even if nothing
	// ended it (a record written before the owner's word reached the hook).
	ownerRequiresHardware(t, iw, false)
	late := newSoftwareKey(t)
	in, err = late.start(iw, late.softwareProof(t, iw))
	if err != nil {
		t.Fatal(err)
	}
	if err := approve(t, iw, in); err != nil {
		t.Fatal(err)
	}
	a, _, _ := iw.org.assetHandler.Store.GetAsset("the-website")
	a.RequireHardwareKey = true
	_ = iw.org.assetHandler.Store.UpsertAsset(a)
	latePerson, _ := iw.org.browserKeys().Whose("the-website", late.tp, time.Now())
	if iw.org.appKeyStillSpeaks("the-website", late.tp, latePerson) {
		t.Fatal("a key in software speaks at an app that requires a hardware key")
	}
}

func TestTheAskTellsTheFrontEndWhatTheOwnerAccepts(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	ask, err := iw.org.beginInstalledAppKey(anAppsRequest("the-website", nil), "", "the-website")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ask.Accepts, ",") != "android,apple,software" {
		t.Fatalf("the ask says %v", ask.Accepts)
	}
	ownerRequiresHardware(t, iw, true)
	ask, _ = iw.org.beginInstalledAppKey(anAppsRequest("the-website", nil), "", "the-website")
	if strings.Join(ask.Accepts, ",") != "android,apple" {
		t.Fatalf("an app that requires a hardware key still says software: %v", ask.Accepts)
	}
}

func TestEndingTheKeysInSoftwareEndsOnlyThemAndTellsTheirBackEnds(t *testing.T) {
	dir := t.TempDir()
	var told []browserKeyRecord
	b := &browserKeys{dataDir: dir, ended: func(r []browserKeyRecord) { told = append(told, r...) }}
	now := time.Now()
	sw, hw := newSoftwareKey(t), newSoftwareKey(t)
	if err := b.RecordSoftwareAppKeyAt("https://app.example", "app", "P", sw.tp, now.Add(time.Hour), now, nil, installedAppFact{Platform: PlatformSoftware}); err != nil {
		t.Fatal(err)
	}
	if err := b.RecordAppKeyAt("https://app.example", "app", "Q", hw.tp, now, nil, installedAppFact{Platform: "android"}); err != nil {
		t.Fatal(err)
	}
	if err := b.RecordSoftwareAppKeyAt("", "app", "R", hw.tp, time.Time{}, now, nil, installedAppFact{Platform: PlatformSoftware}); err == nil {
		t.Fatal("a key in software was kept with no lapse time")
	}
	if n, err := b.EndSoftwareAppKeys("app"); err != nil || n != 1 {
		t.Fatalf("ended %d: %v", n, err)
	}
	if len(told) != 1 || told[0].Thumbprint != sw.tp {
		t.Fatalf("the back end was not told of the software grant alone: %+v", told)
	}
	if _, ok := b.Get("app", hw.tp, now); !ok {
		t.Fatal("ending the keys in software ended a hardware key's grant")
	}
}

func TestOnlyTheOwnerSetsWhetherAHardwareKeyIsRequired(t *testing.T) {
	if _, listed := controllerOwnerOnly["PUT /api/assets/{id}/require-hardware-key"]; !listed {
		t.Fatal("a paired controller could change whether a utility app requires a hardware key")
	}
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	router := chi.NewRouter()
	router.Put("/assets/{id}/require-hardware-key", iw.org.assetHandler.HandleSetRequireHardwareKey)
	put := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/assets/the-website/require-hardware-key", bytes.NewBufferString(body)))
		return w
	}
	if w := put(`{"require_hardware_key": true}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"require_hardware_key":true`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if a, _, _ := iw.org.assetHandler.Store.GetAsset("the-website"); !a.RequireHardwareKey {
		t.Fatal("the setting was not kept with the app's record")
	}
	for _, bad := range []string{`{}`, `{"require_hardware_key": "yes"}`, `{"require_hardware_key": true, "by": "app"}`} {
		if w := put(bad); w.Code != 400 {
			t.Fatalf("%s was taken: %d", bad, w.Code)
		}
	}
	if w := put(`{"require_hardware_key": false}`); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

// The core checks a key held in software as login-go does, on the vector login-dart makes.
func TestTheCoreChecksAKeyInSoftwareAsTheSharedVectorSays(t *testing.T) {
	var v struct {
		P struct {
			AssetID   string `json:"asset_id"`
			Challenge string `json:"challenge_b64u"`
			Thumb     string `json:"thumbprint"`
			Evidence  []byte `json:"evidence"`
			Sig       []byte `json:"key_signature"`
		} `json:"software_proof"`
	}
	raw, err := os.ReadFile("../../packages/login-web/test-vectors/installed-app.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), v.P.Evidence)
	if x == nil {
		t.Fatal("the vector's evidence is not a point")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if tp, _ := thumbprintOfECKey(pub); tp != v.P.Thumb {
		t.Fatal("the core names the key otherwise than the vector")
	}
	ch, _ := base64.RawURLEncoding.DecodeString(v.P.Challenge)
	if err := verifyKeyPossession(PlatformSoftware, pub, v.P.Sig, v.P.AssetID, installedAppAsk{challenge: ch}, v.P.Thumb, ""); err != nil {
		t.Fatalf("the core refuses the shared vector: %v", err)
	}
	if err := verifyKeyPossession(PlatformSoftware, pub, v.P.Sig, "another-app", installedAppAsk{challenge: ch}, v.P.Thumb, ""); err == nil {
		t.Fatal("the core took the signature for another app")
	}
}
