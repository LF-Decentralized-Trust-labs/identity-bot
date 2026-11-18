package server

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/asset"
	"identity-agent-core/secureenclave"
)

// An owner who accepts TPM keys accepts physical chips; a virtual or cloud TPM is
// a declaration of its own, and the proof records which class the key was in.

type virtualWorld struct {
	*anInstalledAppWorld
	sawVirtualAllowed []bool // what each verification was told the owner accepts
}

func aVirtualTPMWorld(t *testing.T, class string, identity func(*asset.InstalledAppIdentity)) *virtualWorld {
	t.Helper()
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	w := &virtualWorld{anInstalledAppWorld: iw}
	iw.said.Platform = "tpm"
	iw.said.EKIssuer = &secureenclave.EKIssuer{Subject: "CN=MSFT-KEYID-1", SHA256: "cd", Class: class}
	inner := verifyTPMInstalledKey
	// A stand-in for the real verifier's rule: a virtual TPM passes only when it is told to allow one.
	verifyTPMInstalledKey = func(ev, ch, credKey []byte, now time.Time, allowVirtual bool) (*secureenclave.InstalledAppKeyFacts, error) {
		w.sawVirtualAllowed = append(w.sawVirtualAllowed, allowVirtual)
		if class == secureenclave.TPMClassVirtual && !allowVirtual {
			return nil, errors.Join(secureenclave.ErrNotAttested, secureenclave.ErrVirtualTPM)
		}
		return inner(ev, ch, credKey, now, allowVirtual)
	}
	a, _, _ := iw.org.assetHandler.Store.GetAsset("the-website")
	identity(&a.InstalledApp)
	if err := iw.org.assetHandler.Store.UpsertAsset(a); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestAVirtualTPMKeyIsAcceptedAndRecordedAsVirtualOnlyForAnOwnerWhoOptedIn(t *testing.T) {
	w := aVirtualTPMWorld(t, secureenclave.TPMClassVirtual, func(i *asset.InstalledAppIdentity) { i.TPMKeys, i.VirtualTPMKeys = true, true })
	f, err := w.org.verifyInstalledAppKey("the-website", w.key, w.proof(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if f.EKClass != secureenclave.TPMClassVirtual || f.EKIssuer != "CN=MSFT-KEYID-1" {
		t.Fatalf("the proof does not record a virtual TPM: %+v", f)
	}
	if len(w.sawVirtualAllowed) != 1 || !w.sawVirtualAllowed[0] {
		t.Fatalf("the verifier was not told the owner opted in: %v", w.sawVirtualAllowed)
	}
}

func TestAVirtualTPMKeyIsRefusedInPlainWordsWhenTheOwnerOnlyAcceptedPhysicalChips(t *testing.T) {
	w := aVirtualTPMWorld(t, secureenclave.TPMClassVirtual, func(i *asset.InstalledAppIdentity) { i.TPMKeys = true })
	_, err := w.org.verifyInstalledAppKey("the-website", w.key, w.proof(), time.Now())
	if err == nil || err.Error() != errVirtualTPM.Error() {
		t.Fatalf("refusal = %v", err)
	}
	if strings.Contains(err.Error(), "MSFT") || strings.Contains(err.Error(), "ErrNotAttested") {
		t.Fatalf("the person is shown a technical reason: %v", err)
	}
	if len(w.sawVirtualAllowed) != 1 || w.sawVirtualAllowed[0] {
		t.Fatalf("the verifier was told virtual is allowed: %v", w.sawVirtualAllowed)
	}
}

// virtual_tpm_keys alone is not tpm_keys: a stored identity that names only it accepts no TPM.
func TestTheVirtualOptInAloneAcceptsNoTPMAtAll(t *testing.T) {
	w := aVirtualTPMWorld(t, secureenclave.TPMClassVirtual, func(i *asset.InstalledAppIdentity) { i.VirtualTPMKeys = true })
	_, err := w.org.verifyInstalledAppKey("the-website", w.key, w.proof(), time.Now())
	if err == nil || err.Error() != errTPMKeysNotAllowed.Error() {
		t.Fatalf("refusal = %v", err)
	}
	if len(w.sawVirtualAllowed) != 0 {
		t.Fatal("the verifier was asked")
	}
}

// If a verifier ever let a virtual proof through for an owner who did not opt in, the core
// would still not keep it.
func TestAVirtualProofTheVerifierLetThroughIsStillRefusedForAnOwnerWhoDidNotOptIn(t *testing.T) {
	w := aVirtualTPMWorld(t, secureenclave.TPMClassVirtual, func(i *asset.InstalledAppIdentity) { i.TPMKeys = true })
	verifyTPMInstalledKey = func(ev, ch, credKey []byte, now time.Time, allowVirtual bool) (*secureenclave.InstalledAppKeyFacts, error) {
		return w.said, nil // a verifier that ignores the owner
	}
	if _, err := w.org.verifyInstalledAppKey("the-website", w.key, w.proof(), time.Now()); err == nil || err.Error() != errVirtualTPM.Error() {
		t.Fatalf("a virtual proof was kept for an owner who did not opt in: %v", err)
	}
	// And a class this build has never heard of is not kept either, opted in or not.
	w.said.EKIssuer.Class = "cloud-ish"
	a, _, _ := w.org.assetHandler.Store.GetAsset("the-website")
	a.InstalledApp.VirtualTPMKeys = true
	_ = w.org.assetHandler.Store.UpsertAsset(a)
	if _, err := w.org.verifyInstalledAppKey("the-website", w.key, w.proof(), time.Now()); err == nil {
		t.Fatal("an unknown class was kept")
	}
}

func TestAPhysicalChipStillSaysPhysicalForAnOwnerWhoOptedInToVirtual(t *testing.T) {
	w := aVirtualTPMWorld(t, secureenclave.TPMClassPhysical, func(i *asset.InstalledAppIdentity) { i.TPMKeys, i.VirtualTPMKeys = true, true })
	f, err := w.org.verifyInstalledAppKey("the-website", w.key, w.proof(), time.Now())
	if err != nil || f.EKClass != secureenclave.TPMClassPhysical {
		t.Fatalf("%+v %v", f, err)
	}
}

// The exchange that comes before the proof is asked the same: the TPM is told virtual is
// allowed only for the owner who opted in, so an opted-in sign-in is not stopped at its first step.
func TestTheCredentialExchangeIsToldVirtualIsAllowedOnlyForAnOwnerWhoOptedIn(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*asset.InstalledAppIdentity)
		want bool
	}{
		{"physical only", func(i *asset.InstalledAppIdentity) { i.TPMKeys = true }, false},
		{"opted in", func(i *asset.InstalledAppIdentity) { i.TPMKeys, i.VirtualTPMKeys = true, true }, true},
		{"virtual only, stored that way", func(i *asset.InstalledAppIdentity) { i.TPMKeys, i.VirtualTPMKeys = false, true }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := aVirtualTPMWorld(t, secureenclave.TPMClassVirtual, tc.set)
			var got []bool
			inner := makeTPMCredentialFor
			t.Cleanup(func() { makeTPMCredentialFor = inner })
			makeTPMCredentialFor = func(req TPMCredentialRequest, key []byte, allowVirtual bool) (*secureenclave.TPMCredential, error) {
				got = append(got, allowVirtual)
				return &secureenclave.TPMCredential{}, nil
			}
			ask, _ := w.org.beginInstalledAppKey(anAppsRequest("the-website", nil), "", "the-website")
			_, err := w.org.makeInstalledAppKeyCredential(anAppsRequest("the-website", nil), "", "the-website", ask.ID, TPMCredentialRequest{})
			if tc.name == "virtual only, stored that way" {
				if err == nil || len(got) != 0 {
					t.Fatalf("a credential was made though tpm_keys is off: %v %v", err, got)
				}
				return
			}
			if err != nil || len(got) != 1 || got[0] != tc.want {
				t.Fatalf("allowVirtual = %v, want %v (%v)", got, tc.want, err)
			}
		})
	}
}

// The owner sees which class each live sign-in's key is in, with the sentence that says what a
// virtual one means; a physical chip carries no warning.
func TestTheOwnerSeesTheClassOfEachKeyAndIsWarnedAboutAVirtualOne(t *testing.T) {
	for _, tc := range []struct {
		class  string
		notice string
	}{
		{secureenclave.TPMClassVirtual, asset.VirtualTPMKeysWarning},
		{secureenclave.TPMClassPhysical, ""},
	} {
		w := aVirtualTPMWorld(t, tc.class, func(i *asset.InstalledAppIdentity) { i.TPMKeys, i.VirtualTPMKeys = true, true })
		w.signedIn(t)
		router := chi.NewRouter()
		router.Get("/assets/{id}/app-key-grants", w.org.handleListAppKeyGrants)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest("GET", "/assets/the-website/app-key-grants", nil))
		var listed []appKeyGrantView
		if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || len(listed) != 1 {
			t.Fatalf("%s", rec.Body.String())
		}
		g := listed[0]
		if g.EKClass != tc.class || g.EKIssuer != "CN=MSFT-KEYID-1" || g.Notice != tc.notice {
			t.Fatalf("%s: grant view = %+v", tc.class, g)
		}
	}
}

// The words the owner reads say what the declaration gives away, in plain terms.
func TestTheOwnersWordsForAVirtualTPMSayTheHostCanReadTheKey(t *testing.T) {
	w := strings.ToLower(asset.VirtualTPMKeysWarning)
	for _, want := range []string{"virtual", "can read", "sign in as"} {
		if !strings.Contains(w, want) {
			t.Errorf("the warning %q does not say %q", asset.VirtualTPMKeysWarning, want)
		}
	}
	for _, bare := range []string{" app ", " agent "} {
		if strings.Contains(" "+w+" ", bare) {
			t.Errorf("the warning says a bare %q", bare)
		}
	}
}
