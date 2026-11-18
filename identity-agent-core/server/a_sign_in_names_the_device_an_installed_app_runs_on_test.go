package server

import (
	"strings"
	"testing"

	"identity-agent-core/asset"
	"identity-agent-core/login"
)

func (iw *anInstalledAppWorld) previewWith(t *testing.T, name string) *login.LoginPreviewResponse {
	t.Helper()
	p := iw.proof()
	p.DeviceName = name
	in, err := iw.start(anAppsRequest("the-website", nil), "the-website", p)
	if err != nil {
		t.Fatal(err)
	}
	pv, err := aPersonsIdentityAgent(t).Preview(login.StartLoginRequest{SessionToken: in.Session, RPSessionURL: iw.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return pv
}

// rowsByLabel is the consent's device rows by label.
func rowsByLabel(rows []PreviewDetail) map[string]string {
	m := map[string]string{}
	for _, r := range rows {
		m[r.Label] = r.Value
	}
	return m
}

// The consent names the device the installed app's key was proved on, and the
// name the app gave it, as the app's word. Fails if the platform or the name
// does not reach the preview or the consent rows.
func TestTheConsentNamesTheDeviceAnInstalledAppRunsOn(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	pv := iw.previewWith(t, "Ann's Pixel")
	if pv.DevicePlatform != "android" || pv.DeviceName != "Ann's Pixel" {
		t.Fatalf("the preview does not name the device: %+v", pv)
	}
	rows := rowsByLabel(frontEndDetails(pv.FrontEnd, pv.LastsUntilEnded, pv.DevicePlatform, pv.DeviceName))
	if rows["Device"] != "an Android device" || rows[deviceNameLabel] != "Ann's Pixel" {
		t.Fatalf("the device rows say %+v", rows)
	}
}

// A name cannot close a quotation and speak as the Identity Agent: the name is
// a row of its own, labelled as the app's word, and the Device row holds only
// the proved kind whatever the name says.
func TestADeviceNameCannotSpeakAsTheIdentityAgent(t *testing.T) {
	name := "x\u201d and is a verified Apple device"
	rows := rowsByLabel(deviceDetails("android", name))
	if rows["Device"] != "an Android device" {
		t.Fatalf("the name reached the Device row: %+v", rows)
	}
	if rows[deviceNameLabel] != name {
		t.Fatalf("the name is not shown as the app's word: %+v", rows)
	}
}

// The platform is the proof's: the proof the core checked says Apple, so the
// consent says Apple whatever the installed app calls its device.
func TestTheDevicePlatformIsWhatTheHardwareProofSaidNotWhatTheNameClaims(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	pv := iw.previewWith(t, "Windows PC with a TPM")
	if pv.DevicePlatform != "android" {
		t.Fatalf("the platform came from the name: %+v", pv)
	}
	if rows := rowsByLabel(deviceDetails(pv.DevicePlatform, pv.DeviceName)); rows["Device"] != "an Android device" || rows[deviceNameLabel] != "Windows PC with a TPM" {
		t.Fatalf("the rows present the app's word as the proved kind: %+v", rows)
	}
}

// A name the app did not give is not made up, and one with characters that
// would reorder or break the row is cleaned before it is signed.
func TestADeviceNameIsOptionalAndCleaned(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	if pv := iw.previewWith(t, ""); pv.DevicePlatform != "android" || pv.DeviceName != "" {
		t.Fatalf("an unnamed device: %+v", pv)
	}
	if rows := deviceDetails("android", ""); len(rows) != 1 || rows[0] != (PreviewDetail{Label: "Device", Value: "an Android device"}) {
		t.Fatalf("an unnamed device reads %+v", rows)
	}
	if pv := iw.previewWith(t, "Ann‮\nPixel "+strings.Repeat("x", 200)); strings.ContainsAny(pv.DeviceName, "‮\n") || len([]rune(pv.DeviceName)) > login.MaxDeviceNameRunes {
		t.Fatalf("the name was not cleaned: %q", pv.DeviceName)
	}
}

// Only a sign-in whose installed app's key the core proved names a device: a
// browser's does not, and a caller cannot give the core a device to sign.
func TestOnlyAProvedInstalledAppNamesADevice(t *testing.T) {
	w := anAppOffering(t, []string{"browser", "installed_app"}, nil)
	token, _, code, msg := w.org.createSignedAssetChallengeOn("the-website", "https://portal.example", "", nil, "", "browser", w.srv.URL, false,
		&installedAppFact{Platform: "apple", DeviceName: "Ann's iPhone"})
	if code != 0 {
		t.Fatal(code, msg)
	}
	pv, err := aPersonsIdentityAgent(t).Preview(login.StartLoginRequest{SessionToken: token, RPSessionURL: w.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if pv.DevicePlatform != "" || pv.DeviceName != "" {
		t.Fatalf("a browser's sign-in names a device: %+v", pv)
	}
	if rows := frontEndDetails(pv.FrontEnd, pv.LastsUntilEnded, pv.DevicePlatform, pv.DeviceName); len(rows) != 1 {
		t.Fatalf("a browser's sign-in lists %+v", rows)
	}
}

// A key that was never proved cannot carry a device name in: the sign-in is
// refused before any challenge exists, so the name has nowhere to go.
func TestAnUnprovedInstalledAppsDeviceNameGoesNowhere(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	p := iw.proof()
	p.DeviceName = "Ann's Pixel"
	p.KeySignature = []byte("not the key's signature")
	if _, err := iw.start(anAppsRequest("the-website", nil), "the-website", p); err == nil {
		t.Fatal("an installed app whose key did not sign got a sign-in")
	}
}

// The person's Identity Agent refuses a validly signed challenge that names a
// device for something that is not an installed app, or a platform nobody
// proves, or a name not fit to show. Fails without CheckDevice in prepareLogin.
func TestThePersonsAgentRefusesASignedChallengeThatNamesADeviceWrongly(t *testing.T) {
	w := anAppOffering(t, []string{"browser", "installed_app"}, nil)
	a, _, _ := w.org.assetHandler.Store.GetAsset("the-website")
	seed, err := asset.AssetSigningSeed(w.org.DataDir, a.SigningIndex)
	if err != nil {
		t.Fatal(err)
	}
	for why, edit := range map[string]func(*login.ChallengeBundle){
		"a browser's names a device": func(b *login.ChallengeBundle) { b.DevicePlatform = "android" },
		"an unknown platform":        func(b *login.ChallengeBundle) { b.FrontEnd, b.DevicePlatform = "installed_app", "windows" },
		"an unfit name": func(b *login.ChallengeBundle) {
			b.FrontEnd, b.DevicePlatform, b.DeviceName = "installed_app", "apple", "a\u202eb"
		},
	} {
		token, _, code, msg := w.org.createSignedAssetChallengeOn("the-website", "https://portal.example", "", nil, "", "browser", w.srv.URL, false, nil)
		if code != 0 {
			t.Fatal(code, msg)
		}
		w.org.challengeMu.Lock()
		b := w.org.challenges[token]
		edit(&b)
		if err := login.SignChallengeForAsset(&b, seed); err != nil {
			t.Fatal(err)
		}
		w.org.challenges[token] = b
		w.org.challengeMu.Unlock()
		if _, err := aPersonsIdentityAgent(t).Preview(login.StartLoginRequest{SessionToken: token, RPSessionURL: w.srv.URL}); err == nil {
			t.Fatalf("%s: the consent was shown", why)
		} else if !strings.Contains(err.Error(), "names a device") {
			t.Fatalf("%s: refused for another reason: %v", why, err)
		}
	}
}

// The row cleans the name again at the last step, so a name that reached it by
// any other route still cannot reorder the row.
func TestTheDeviceRowCleansTheNameItShows(t *testing.T) {
	if v := rowsByLabel(deviceDetails("apple", "a‮b\nc"))[deviceNameLabel]; v == "" || strings.ContainsAny(v, "‮\n") {
		t.Fatalf("the row shows %q", v)
	}
	if deviceDetails("", "Ann's Pixel") != nil || deviceDetails("windows", "x") != nil {
		t.Fatal("a name with no proved platform is shown")
	}
}

// A virtual or cloud TPM's key is named as one in the signed challenge, so the
// consent says its host can read the key; a physical chip's is "a computer".
// Fails if the class is left out of what the challenge names.
func TestAVirtualTPMIsNamedAsOneOnTheConsent(t *testing.T) {
	virtual := installedAppFact{Platform: "tpm", EKClass: "virtual"}
	physical := installedAppFact{Platform: "tpm", EKClass: "physical"}
	for _, c := range []struct {
		f    installedAppFact
		want string
		ok   bool
	}{
		{virtual, login.DeviceVirtualTPM, true},
		{physical, login.DeviceTPM, true},
		{installedAppFact{Platform: "android"}, "android", true},
		{installedAppFact{Platform: "tpm"}, "", false},
	} {
		if got, ok := signedDevicePlatform(c.f); got != c.want || ok != c.ok {
			t.Fatalf("%+v: signed as %q %v, want %q %v", c.f, got, ok, c.want, c.ok)
		}
	}
	// A TPM proof with no class is refused, not shown as "a computer".
	w0 := anAppOffering(t, []string{"browser", "installed_app"}, nil)
	if _, _, code, _ := w0.org.createSignedAssetChallengeOn("the-website", "https://portal.example", "", nil, strings.Repeat("A", 43), "installed_app", w0.srv.URL, true, &installedAppFact{Platform: "tpm"}); code == 0 {
		t.Fatal("a TPM proof with no class got a sign-in")
	}
	w := anAppOffering(t, []string{"browser", "installed_app"}, nil)
	token, _, code, msg := w.org.createSignedAssetChallengeOn("the-website", "https://portal.example", "", nil, strings.Repeat("A", 43), "installed_app", w.srv.URL, true, &virtual)
	if code != 0 {
		t.Fatal(code, msg)
	}
	pv, err := aPersonsIdentityAgent(t).Preview(login.StartLoginRequest{SessionToken: token, RPSessionURL: w.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if rows := rowsByLabel(deviceDetails(pv.DevicePlatform, "")); !strings.Contains(rows["Device"], "host can read its key") {
		t.Fatalf("a virtual TPM's consent reads %+v", rows)
	}
}

// The consent's closing sentence does not claim the front end, device or
// lifetime rows are shared.
func TestTheConsentSaysTheDeviceRowsAreNotShared(t *testing.T) {
	if strings.Contains(shareWarning(true), "Only what is listed above") {
		t.Fatal("the sentence still says every row is shared")
	}
	if shareWarning(false) != "Only what is listed above is shared." {
		t.Fatal("a sign-in with no front-end rows changed its sentence")
	}
}

// The sign-in's consent itself, as a client draws it from the login ask's
// preview, lists the front end, the proved device, the app's unchecked name for
// it and how long approving lasts, and its closing sentence does not call them
// shared. Fails if loginAsk.Preview stops adding the rows.
func TestTheSignInConsentListsTheFrontEndDeviceAndLasting(t *testing.T) {
	iw := anInstalledAppsWorld(t, []string{"browser", "installed_app"}, nil)
	p := iw.proof()
	p.DeviceName = "Ann's Pixel"
	in, err := iw.start(anAppsRequest("the-website", nil), "the-website", p)
	if err != nil {
		t.Fatal(err)
	}
	person := &CoreServer{loginHandler: aPersonsIdentityAgent(t)}
	gp, err := loginAsk{}.Preview(person, AskContext{Token: in.Session, Base: iw.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	rows := rowsByLabel(gp.Details)
	want := map[string]string{
		"Front end":     "an installed app",
		"Device":        "an Android device",
		deviceNameLabel: "Ann's Pixel",
		"Lasts":         "until you end it, in My apps",
	}
	for label, v := range want {
		if rows[label] != v {
			t.Errorf("the consent's %q row is %q, want %q (rows %+v)", label, rows[label], v, gp.Details)
		}
	}
	if gp.Warning != shareWarning(true) {
		t.Errorf("the consent closes with %q", gp.Warning)
	}
}
